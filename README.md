# pcap2parquet
Create parquet files from network packet captures (pcap files).

### Why?
Analysing pcaps can be tricky, especially if you are not used to working with the tools that are frequently used for analysing pcaps (wireshark, tshark, ...).

If you are fairly comfortable using SQL, then you can use [duckdb](https://duckdb.org/) for easy analysis with the resulting parquet files, as duckdb can process these natively!

See below for an example.

## requirements
You need to have [tshark](https://tshark.dev/) and tcpdump installed (and on the path) as both are called by pcap2parquet.

They are invoked without `sudo`, so make sure both can be executed by your user account. 
tcpdump is used to split bigger pcap files into smaller chunks before processing, it does not need access to network interfaces.
(simply do a `tcpdump -r <pcap file>` to check permissions are set properly)
## Usage

```commandline
usage: pcap2parquet.py [-h] [-l] [-r] [--debug] [-V] source parquetdir

Convert pcap file(s) (produced by tshark, tcpdump, snort or others) to parquet format

positional arguments:
  source                Source pcap file or directory containing pcap files
  parquetdir            Directory where to store resulting parquet files

options:
  -h, --help            show this help message and exit
  -l, --log_parse_errors
                        Any lines that cannot be parsed will be stored in a file
                        The filename is equal to the file being processed, 
                        with '-parse-errors.txt' appended. It will be stored
                        in the current working directory
  -r, --recursive       recursively searches for pcap files if source specifies a directory.
  --debug               show debug output
  -V, --version         print version and exit
```

### example
```commandline
./pcap2parquet.py sample1.pcap .
```

Resulting parquet files are stored in the parquetdir (destination directory) with the same name as the original file, appended with '.parquet'.

If the source points to a directory then all pcap files in that directory will be converted to parquet files and stored in the destination directory.


## Using duckdb

To analyse resulting parquet file using duckdb, install and fire up the duckdb cli.
Then do something like:

```commandline
# Create a view from the contents of the 'sample.parquet' file in the current working directory
# This way the contents will not be loaded into memory (as opposed to 'create table')

create view pcap as select * from 'sample.parquet';

# describe the structure of the pcap view:
describe pcap;

┌─────────────────────┬─────────────┬─────────┬─────────┬─────────┬───────┐
│     column_name     │ column_type │  null   │   key   │ default │ extra │
│       varchar       │   varchar   │ varchar │ varchar │ varchar │ int32 │
├─────────────────────┼─────────────┼─────────┼─────────┼─────────┼───────┤
│ frame_time          │ TIMESTAMP   │ YES     │         │         │       │
│ ip_src              │ VARCHAR     │ YES     │         │         │       │
│ ip_dst              │ VARCHAR     │ YES     │         │         │       │
│ ip_proto            │ UTINYINT    │ YES     │         │         │       │
│ tcp_flags           │ VARCHAR     │ YES     │         │         │       │
│ col_source          │ VARCHAR     │ YES     │         │         │       │
│ col_destination     │ VARCHAR     │ YES     │         │         │       │
│ col_protocol        │ VARCHAR     │ YES     │         │         │       │
│ dns_qry_name        │ VARCHAR     │ YES     │         │         │       │
│ dns_qry_type        │ VARCHAR     │ YES     │         │         │       │
│ eth_type            │ USMALLINT   │ YES     │         │         │       │
│ frame_len           │ USMALLINT   │ YES     │         │         │       │
│ udp_length          │ USMALLINT   │ YES     │         │         │       │
│ http_request_uri    │ VARCHAR     │ YES     │         │         │       │
│ http_host           │ VARCHAR     │ YES     │         │         │       │
│ http_request_method │ VARCHAR     │ YES     │         │         │       │
│ http_user_agent     │ VARCHAR     │ YES     │         │         │       │
│ icmp_type           │ UTINYINT    │ YES     │         │         │       │
│ ip_frag_offset      │ USMALLINT   │ YES     │         │         │       │
│ ip_ttl              │ UTINYINT    │ YES     │         │         │       │
│ ntp_priv_reqcode    │ VARCHAR     │ YES     │         │         │       │
│ tcp_dstport         │ USMALLINT   │ YES     │         │         │       │
│ tcp_srcport         │ USMALLINT   │ YES     │         │         │       │
│ udp_dstport         │ USMALLINT   │ YES     │         │         │       │
│ udp_srcport         │ USMALLINT   │ YES     │         │         │       │
│ col_info            │ VARCHAR     │ YES     │         │         │       │
│ pcap_file           │ VARCHAR     │ YES     │         │         │       │
├─────────────────────┴─────────────┴─────────┴─────────┴─────────┴───────┤
│ 27 rows                                                       6 columns │
└─────────────────────────────────────────────────────────────────────────┘

# Return the number of rows in pcap
select count(*) from pcap;
┌──────────────┐
│ count_star() │
│    int64     │
├──────────────┤
│        28683 │
└──────────────┘

# List the different IP destinations and the number of packet with that destination
# Order by number of packets (descending order) and limit to the first 10

select ip_dst, count() as count from pcap group by ip_dst order by count desc limit 10;
┌────────────────┬────────┐
│     ip_dst     │ count  │
│    varchar     │ int64  │
├────────────────┼────────┤
│ 172.16.139.250 │ 181258 │
│ 68.64.21.62    │  25733 │
│ 172.16.133.57  │  19723 │
│ 172.16.133.26  │  17767 │
│ 67.217.64.99   │  16875 │
│ 157.56.240.102 │  14851 │
│ 172.16.133.78  │  13602 │
│ 172.16.133.36  │  11675 │
│ 172.16.133.25  │  11569 │
│ 172.16.133.39  │  10818 │
├────────────────┴────────┤
│ 10 rows       2 columns │
└─────────────────────────┘
```

