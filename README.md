# 404toggle
Multi-threaded script to quickly disable/enable active CDN containers. Up to 90 threads.
```
./404toggle.py -h
usage: 404toggle.py [-h] [-u USERNAME] [-k APIKEY] [-r REGION]

disable and renable cdn containers region wide

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --user USERNAME
                        User on account
  -k APIKEY, --key APIKEY
                        API Key of User
  -r REGION, --region REGION
                        Region to mess wit
```

## Usage
Script is in python3 so ensure your virtual environment is set. You then need to install requests.
```
pip install -r requirements.txt
```
You can then run it against a region
```
./404toggle.py -u $USER_NAME -k $API_KEY -r $REGION
```

## Known issues
There is currently a race condition if utilizing too many threads. This will cause the consumers to start dying out before they get their workload. You will know if you are being affected by this if your threadcount (tc=$n) starts lowering while there are still objects in the queue. It should only occur when utilizing 32+ CPUs

Current workaround:  
Get less CPUs :(
