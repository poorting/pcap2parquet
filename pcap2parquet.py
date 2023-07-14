#! /usr/bin/env python3
import os
import io
import sys
import shutil
import time
import logging
import pprint
import argparse
import textwrap
import tempfile
from pathlib import Path
import subprocess
import multiprocessing
import re
from io import StringIO
import random
import string

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.dataset as ds
import pyarrow.parquet as pq
import pyarrow.csv
import dateutil.parser
import datetime

program_name = os.path.basename(__file__)
VERSION = 0.1
logger = logging.getLogger(__name__)

# Match snort.log.* and *.pcap files
pattern = "snort\.log.*|.*\.pcap"


###############################################################################
# taken from https://stackoverflow.com/questions/69156181/pyarrow-find-bad-lines-in-csv-to-parquet-conversion
# Since some pcap->csv may have UTF-8 errors
class UnicodeErrorIgnorerIO(io.IOBase):
    """Simple wrapper for a BytesIO that removes non-UTF8 input.

    If a file contains non-UTF8 input, it causes problems in pyarrow and other libraries
    that try to decode the input to unicode strings. This just removes the offending bytes.

    >>> io = io.BytesIO(b"INT\xbfL LICENSING INDUSTRY MERCH ASSOC")
    >>> io = UnicodeErrorIgnorerIO(io)
    >>> io.read()
    'INTL LICENSING INDUSTRY MERCH ASSOC'
    """

    def __init__(self, file: io.BytesIO) -> None:
        self.file = file

    def read(self, n=-1):
        return self.file.read(n).decode("utf-8", "ignore").encode("utf-8")

    def readline(self, n=-1):
        return self.file.readline(n).decode("utf-8", "ignore").encode("utf-8")

    def readable(self):
        return True


###############################################################################
class Pcap2Parquet:

    PCAP_COLUMN_NAMES: dict[str, dict] = {
        '_ws.col.Time': {'frame_time': pa.timestamp('us')},
        'ip.src': {'ip_src': pa.string()},
        'ip.dst': {'ip_dst': pa.string()},
        'ip.proto': {'ip_proto': pa.uint8()},
        'tcp.flags.str': {'tcp_flags': pa.string()},
        '_ws.col.Source': {'col_source': pa.string()},
        '_ws.col.Destination': {'col_destination': pa.string()},
        '_ws.col.Protocol': {'col_protocol': pa.string()},
        'dns.qry.name': {'dns_qry_name': pa.string()},
        'dns.qry.type': {'dns_qry_type': pa.string()},
        'eth.type': {'eth_type': pa.uint16()},
        'frame.len': {'frame_len': pa.uint16()},
        'udp.length': {'udp_length': pa.uint16()},
        'http.request.uri': {'http_request_uri': pa.string()},
        'http.host': {'http_host': pa.string()},
        'http.request.method': {'http_request_method': pa.string()},
        'http.user_agent': {'http_user_agent': pa.string()},
        'icmp.type': {'icmp_type': pa.uint8()},
        'ip.frag_offset': {'ip_frag_offset': pa.uint16()},
        'ip.ttl': {'ip_ttl': pa.uint8()},
        'ntp.priv.reqcode': {'ntp_priv_reqcode': pa.string()},
        'tcp.dstport': {'tcp_dstport': pa.uint16()},
        'tcp.srcport': {'tcp_srcport': pa.uint16()},
        'udp.dstport': {'udp_dstport': pa.uint16()},
        'udp.srcport': {'udp_srcport': pa.uint16()},
        '_ws.col.Info': {'col_info': pa.string()},
    }

    # Max size of chunk to read at a time
    block_size = 512 * 1024 * 1024

    chunks = None
    chunks_csv = None

    # ------------------------------------------------------------------------------
    def __init__(self, source_file: str, destination_dir: str, log_parse_errors=False, nr_procs=2):
        """Initialises Nfdump2Parquet instance.

        Provide nfdump_fields parameter **only** if defaults don't work
        Defaults for parquet_fields: ts, te, td, sa, da, sp, dp, pr, flg, ipkt, ibyt, opkt, obyt

        :param source_file: name of the nfcapd file to convert
        :param destination_dir: directory for storing resulting parquet file
        :param parquet_fields: the fields from ncapd file to translate to parquet
        :param nfdump_fields: the fields (and order) in the nfcapd file
        """
        if not os.path.isfile(source_file):
            raise FileNotFoundError(source_file)
        self.src_file = source_file
        self.basename = os.path.basename(source_file)
        self.dst_dir = destination_dir
        if not self.dst_dir.endswith('/'):
            self.dst_dir = f"{self.dst_dir}/"
        self.parse_errors = 0
        self.log_parse_errors = log_parse_errors
        self.nr_procs = int(nr_procs)

        letters = string.ascii_lowercase
        self.random = ''.join(random.choice(letters) for i in range(10))
        self.splitsize = 100
        # MB

    # ------------------------------------------------------------------------------
    def __prepare_file(self):

        # Chop up a file into multiple chunks if it is bigger than a certain size
        # Returns either a list of chunk files or the same single file

        use_tmp = False
        filename = Path(self.src_file)
        if filename.stat().st_size < (self.splitsize*1000*1000):  # PCAP is smaller than 100MB
            self.chunks = [self.src_file]
        else:
            # Now check if the file ends in .pcap
            # If not: tcpdump on Ubuntu variants will return permission denied
            # when splitting into multiple chunks
            # Solution: copy to tmp folder with extension .pcap...
            if not self.src_file.endswith('.pcap'):
                logger.debug(f'Copy/rename file since it does not end in .pcap')
                shutil.copyfile(self.src_file, f'/tmp/{self.random}.pcap')
                filename = Path(f'/tmp/{self.random}.pcap')
                use_tmp = True
            logger.debug(f'Splitting PCAP file {filename} into chunks of {self.splitsize}MB.')
            process = subprocess.run(
                ['tcpdump', '-r', filename, '-w', f'/tmp/pcap2parquet_{self.random}_chunk', '-C', f'{self.splitsize}'],
                stderr=subprocess.PIPE)
            output = process.stderr
            if process.returncode != 0:
                err = output.decode('utf-8').strip()
                logger.error(f'splitting file failed: {err}')
            else:
                self.chunks = [Path(rootdir) / file for rootdir, _, files in os.walk('/tmp')
                               for file in files if file.startswith(f'pcap2parquet_{self.random}_chunk')]
                logger.debug(f"Split into {len(self.chunks)} chunks")

            if use_tmp:
                os.remove(filename)

    # ------------------------------------------------------------------------------
    def __cleanup(self):
        if self.chunks:
            if len(self.chunks) > 1:
                for chunk in self.chunks:
                    os.remove(chunk)
            self.chunks = None

        if self.chunks_csv:
            if len(self.chunks_csv) > 1:
                for chunk in self.chunks_csv:
                    os.remove(chunk)
            self.chunks_csv = None

    # ------------------------------------------------------------------------------
    def __parse_error(self, row):
        # logger.debug(row.text)
        self.parse_errors += 1
        if self.log_parse_errors:
            # Append to file
            with open(self.basename+'-parse-errors.txt', 'a', encoding='utf-8') as f:
                f.write(row.text+'\n')
        return 'skip'

    # ------------------------------------------------------------------------------
    def convert_chunk_to_csv(self, pcap_chunk):
        # Create the list of columns tshark has to export to CSV
        col_extract = list(self.PCAP_COLUMN_NAMES.keys())

        new_env = dict(os.environ)
        new_env['LC_ALL'] = 'C.utf8'
        new_env['LC_TIME'] = 'POSIX'
        new_env['LC_NUMERIC'] = 'C.utf8'

        tmp_file, tmp_filename = tempfile.mkstemp()
        # tshark_error = False
        # Create command
        csv_file = None
        command = ['tshark', '-r', str(pcap_chunk), '-t', 'ud', '-T', 'fields']
        for field in col_extract:
            command.extend(['-e', field])
        for option in ['header=n', 'separator=/t', 'quote=n', 'occurrence=f']:
            command.extend(['-E', option])

        logger.debug(" ".join(command))
        try:
            process = subprocess.run(command, stdout=tmp_file, stderr=subprocess.PIPE, env=new_env)
            output = process.stderr
            if process.returncode != 0:
                err = output.decode('utf-8')
                logger.error(f'tshark command failed:{err}')
                os.close(tmp_file)
                os.remove(tmp_filename)
            else:
                if len(output) > 0:
                    err = output.decode('utf-8')
                    for errline in err.split('\n'):
                        if len(errline) > 0:
                            logger.warning(errline)
                os.close(tmp_file)
                csv_file = tmp_filename
        except Exception as e:
            logger.error(f'Error reading {str(pcap_chunk)} : {e}')
            pp.pprint(e)
            os.close(tmp_file)
            os.remove(tmp_filename)

        return csv_file

    # ------------------------------------------------------------------------------
    def convert(self):

        pp = pprint.PrettyPrinter(indent=4)

        # Create the list of columns tshark has to export to CSV
        col_extract = list(self.PCAP_COLUMN_NAMES.keys())

        # Create the list of names pyarrow gives to the columns in the CSV
        col_names = []
        for extr_name in col_extract:
            col_names.append(next(iter(self.PCAP_COLUMN_NAMES[extr_name])))

        # Dict mapping column names to the pyarrow types
        col_type = {}
        [col_type.update(valtyp) for valtyp in self.PCAP_COLUMN_NAMES.values()]

        start = time.time()

        # Split source pcap into chunks if need be
        self.__prepare_file()
        if not self.chunks:
            logger.error("conversion aborted")
            return None

        # Convert chunks to csv individually and in parallel
        pool = multiprocessing.Pool(self.nr_procs)
        results = pool.map(self.convert_chunk_to_csv, self.chunks)  # Convert the PCAP chunks concurrently
        pool.close()
        pool.join()

        self.chunks_csv = []
        for result in results:
            if result:
                self.chunks_csv.append(result)

        duration = time.time() - start
        sf = os.path.basename(self.src_file)
        logger.debug(f"{sf} to CSV in {duration:.2f}s")
        start = time.time()

        pqwriter = None

        # Now read the produced CSVs and convert them to parquet one by one
        for chunknr, chunkcsv in enumerate(self.chunks_csv):
            logger.debug(f"Writing to parquet: {chunknr+1}/{len(self.chunks_csv)}")
            try:
                with open(chunkcsv, "rb") as f:
                    f = UnicodeErrorIgnorerIO(f)
                    with pyarrow.csv.open_csv(
                                              input_file=f,
                                              # input_file='tmp.csv',
                                              read_options=pyarrow.csv.ReadOptions(
                                                  block_size=self.block_size,
                                                  column_names=col_names,
                                                  encoding='utf-8',
                                              ),
                                              parse_options=pyarrow.csv.ParseOptions(
                                                  delimiter='\t',
                                                  # quote_char="'",
                                                  invalid_row_handler=self.__parse_error
                                              ),
                                              convert_options=pyarrow.csv.ConvertOptions(
                                                  timestamp_parsers=[pyarrow.csv.ISO8601],
                                                  column_types=col_type,
                                              ),
                                              ) as reader:
                        for next_chunk in reader:
                            if next_chunk is None:
                                break
                            table = pa.Table.from_batches([next_chunk])
                            # Add a column with the basename of the source file
                            # This will allow detailed investigation of the proper
                            # original pcap file with tshark if needed
                            table = table.append_column('pcap_file', pa.array([self.basename] * len(table), pa.string()))

                            if not pqwriter:
                                pqwriter = pq.ParquetWriter(f'{self.dst_dir}{self.basename}.parquet', table.schema)

                            pqwriter.write_table(table)

            except pyarrow.lib.ArrowInvalid as e:
                logger.error(e)

        if pqwriter:
            pqwriter.close()
            duration = time.time() - start
            logger.debug(f"CSV to Parquet in {duration:.2f}s")

        self.__cleanup()
        return True


###############################################################################
class ArgumentParser(argparse.ArgumentParser):

    def error(self, message):
        print('\n\033[1;33mError: {}\x1b[0m\n'.format(message))
        self.print_help(sys.stderr)
        # self.exit(2, '%s: error: %s\n' % (self.prog, message))
        self.exit(2)


###############################################################################
class CustomConsoleFormatter(logging.Formatter):
    """
        Log facility format
    """

    def format(self, record):
        # info = '\033[0;32m'
        info = ''
        warning = '\033[0;33m'
        error = '\033[1;33m'
        debug = '\033[1;34m'
        reset = "\x1b[0m"

        formatter = "%(levelname)s - %(message)s"
        if record.levelno == logging.INFO:
            log_fmt = info + formatter + reset
            self._style._fmt = log_fmt
        elif record.levelno == logging.WARNING:
            log_fmt = warning + formatter + reset
            self._style._fmt = log_fmt
        elif record.levelno == logging.ERROR:
            log_fmt = error + formatter + reset
            self._style._fmt = log_fmt
        elif record.levelno == logging.DEBUG:
            # formatter = '%(asctime)s %(levelname)s [%(filename)s.py:%(lineno)s/%(funcName)s] %(message)s'
            formatter = '%(levelname)s [%(filename)s:%(lineno)s/%(funcName)s] %(message)s'
            log_fmt = debug + formatter + reset
            self._style._fmt = log_fmt
        else:
            self._style._fmt = formatter

        return super().format(record)


###############################################################################
# Subroutines
def get_logger(args):
    logger = logging.getLogger(__name__)

    # Create handlers
    console_handler = logging.StreamHandler()
    #    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter = CustomConsoleFormatter()
    console_handler.setFormatter(formatter)

    logger.setLevel(logging.INFO)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    # add handlers to the logger
    logger.addHandler(console_handler)

    return logger


# ------------------------------------------------------------------------------
def parser_add_arguments():
    """
        Parse command line parameters
    """
    parser = ArgumentParser(
        prog=program_name,
        description=textwrap.dedent('''\
                        Convert pcap file(s) (produced by tshark, tcpdump, snort or others) to parquet format
                        '''),
        formatter_class=argparse.RawTextHelpFormatter, )

    parser.add_argument("source",
                        help=textwrap.dedent('''\
                        Source pcap file or directory containing pcap files
                        '''),
                        action="store",
                        )

    parser.add_argument("parquetdir",
                        help=textwrap.dedent('''\
                        Directory where to store resulting parquet files
                        '''),
                        action="store",
                        )

    parser.add_argument("-l", "--log_parse_errors",
                        help=textwrap.dedent('''\
                        Any lines that cannot be parsed will be stored in a file
                        The filename is equal to the file being processed, 
                        with '-parse-errors.txt' appended. It will be stored
                        in the current working directory
                        '''),
                        action="store_true",
                        )

    parser.add_argument("-r", "--recursive",
                        help="recursively searches for pcap files if source specifies a directory.",
                        action="store_true")

    parser.add_argument("-n",
                        help="Number of processes in parallel to convert.\n"\
                        f"Default is the number of cores divided by two",
                        action="store",
                        default=0,
                        type=int)

    parser.add_argument("--debug",
                        help="show debug output",
                        action="store_true")

    parser.add_argument("-V", "--version",
                        help="print version and exit",
                        action="version",
                        version='%(prog)s (version {})'.format(VERSION))

    return parser


# ------------------------------------------------------------------------------
def list_files(directory, recursive=False):
    filelist = []
    if not os.path.isdir(directory):
        return filelist

    if not directory.endswith("/"):
        directory = directory + '/'
    with os.scandir(directory) as it:
        for entry in it:
            if not entry.name.startswith('.'):
                if entry.is_file():
                    if re.match(pattern, entry.name):
                        filelist.append('{0}{1}'.format(directory, entry.name))
                elif recursive:
                    filelist.extend(list_files(directory + entry.name, recursive))

    return filelist


###############################################################################
def main():
    pp = pprint.PrettyPrinter(indent=4)
    parser = parser_add_arguments()
    args = parser.parse_args()

    logger = get_logger(args)

    filelist = []
    filename = args.source

    if os.path.isdir(filename):
        filelist = list_files(filename, args.recursive)
    else:
        filelist.append(filename)

    filelist = sorted(filelist)
    # pp.pprint(filelist)

    nr_of_processes = args.n
    if nr_of_processes == 0:
        nr_of_processes = 2
        if os.cpu_count():
            nr_of_processes = int(os.cpu_count()/2)

    logger.info(f"Using up to {nr_of_processes} cores for conversion")

    for filename in filelist:
        logger.info(f'converting {filename}')
        try:
            start = time.time()
            pcap2pqt = Pcap2Parquet(filename, args.parquetdir, args.log_parse_errors, nr_of_processes)
            ret = pcap2pqt.convert()
            duration = int(time.time() - start)
            if ret:
                logger.info(f"conversion took {duration} seconds")
            if pcap2pqt.parse_errors > 0:
                logger.info(f'{pcap2pqt.parse_errors} parse errors during conversion, these lines were skipped')
        except FileNotFoundError as fnf:
            logger.error(f'File not found: {fnf}')
            exit(2)


###############################################################################
if __name__ == '__main__':
    # Run the main process
    main()
