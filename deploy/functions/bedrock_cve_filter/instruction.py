import os

resource = os.environ.get('resource')
instruction = ("""Read the following exploitation and identify if resource on my system is vulnerable to the exploitation. The System that I am using is including %s. 
read the exploitation carefully and see if any vulnerability match the system that I am using 
if it match return {"status": 200} only if not return {"status": 0} only in json. Please return only the JSON no need to include ''' or json or any desPribtion please follow the instruction strictly""" %resource)