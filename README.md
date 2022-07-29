# nsid_ark

This repository is very similar to the ArkDNS one. The difference with this reposotory is the addition in tophour.py of getting servers' nsids and adding it to the files. 

This repository is used on CAIDA Ark nodes.

Each node has its own folder (i.e. beg-rs, san-us, etc.)

The program run on each node is tophour.py, to run on a node simply cd into the correct folder (matches with the node you are sshed into) and then use the following command: nohup python3 ../tophour.py & (or /usr/local/ark/bin/python3 ../tophour.py & if python3 is not liking the dnspython package you tried to pip install in)

I would push the results to the github repository, which makes management of the data fairly easy.

The timeout_counter.py program simply totals how many occurances of TIME OUT show up in the data.

The timechecker_unfinished folder has programs that never worked reliably on the nodes.


In untested_extra there are two different programs that could be beneficial, they just haven't been run for more then 15 minutes.

The program origin.py uses the default resolver and an nxdomain causing request to see if a root server is updated after 60 seconds.

The program double.py tests the UNBOUND and BIND resolvers. A faulty request is sent every n seconds to all the root servers. As soon as a change is detected, a new bad request is sent through the BIND resolver that needs to be set up on the machine this is being run on. A new serial is returned and compared to see if the SOA is updated. The program then switches the resolver to UNBOUND and the same process is repeated after switching the resolver back to BIND. This continues until the user terminates the program. This is an automated version of what I did to do the initial tests on the solvers to check out negative caching.

