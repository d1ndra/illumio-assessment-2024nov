# Illumio Technical Assessment


To execute the code execute `process.py` with the following options:
- `-logfile`: the file containing the logs
- `-lookupfile`: the csv file containing the lookup info (optional). If not provided it will be read from "lookup.csv" in the current folder
- `-outputfile`: the output file to write the output to (optional). If not provided, the output will be written to "output.txt"


Example command:

```python process.py -logfile logs.txt -outputfile out.txt -lookupfile lookup.csv```

## Other info
The information in each log line was referred to using the [available fields](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html#flow-logs-fields) on the AWS Flog log records page.

From the fields present, the protocol information was stored in the `proto_info` dictionary.

The `proto_info` has been fetched from the [IANA Protocol Numbers page](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml).
Example info stored in protocol.txt and processed using code:
``` python
with open ('protocols.txt') as f:
    proto_info = {}
    for line in f:
        info = line.strip().split()
        info_dec = info[0].strip()
        info_keyword = info[1].strip().lower()
        if info_dec and info_keyword:
            proto_info[info_dec] = info_keyword
```



## Assumptions:
- Tags are the same in both the lower and upper case. Eg. `sv_p1` is the same as `sv_P1`. The output has the tags in lower case irrespective of the input.
- Only version 2 of the logs are supported, any logs not of version 2 will be discarded.
- Each log should have at least 8 fields present.


## Tested:
- With various files provided or not
- With empty lookup file
- With various protocols