# inform_protocol
Encode and decode the inform protocol from unifi

## inform_sniffer.py

```
virtualenv -p python3 venv
. /venv/bin/activate
pip install -r requirements.txt
#python inform_sniffer.py <actualinformURL> <management key>
python inform_sniffer.py http://unifi:8080/ 0123456789abcdef...
```

Then you need to set the inform location on the device

```
ssh admin@ap
# set-inform http://location_of_sniffer:port/
```

Don't forget to set the inform back to the real controller when done
