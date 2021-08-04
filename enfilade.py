#!/usr/bin/python

'''
Original BSD License (BSD with advertising)

Copyright (c) 2021, {Aditya K Sood - https://adityaksood.com}
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of SecNiche Security Labs nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.
    
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
'''

# importing required libraries for successful execution of this tool

lib_requirements = ['os','re','pymongo','time','sys','urllib','urllib2','requests','json','geoip']
for import_library in lib_requirements:
    try:
        globals()[import_library] = __import__(import_library)
    except:
        print "[-] %s - import library failed !" %(import_library)
        print "[-] tool cannot continue, please install the required library !"
        print "[*] sudo apt-get install python-setuptools to install 'easy_install'"
        sys.exit(0)
try:
    from bson.json_util import dumps
except:
    print "[-] import library failed for JSON Dumps !"



def banner():
    print "\t--------------------------------------------------------------------"
    cs_banner = """   
	   _____  ____________   ___   ___  ____
	  / __/ |/ / __/  _/ /  / _ | / _ \/ __/
	 / _//    / _/_/ // /__/ __ |/ // / _/  
	/___/_/|_/_/ /___/____/_/ |_/____/___/ 

	ENFILADE : A Tool to Detect Potential Infections in MongoDB Deployments !
        Authored by: Aditya K Sood {https://adityaksood.com} 
        """
    print cs_banner
    print "\t--------------------------------------------------------------------"



def mongo_auth_check(host,port):
	try:
		target= str(host + ":" + str(port))
        	print "[*] Target : <%s>" %target
		m_client = pymongo.MongoClient(host = str(target),serverSelectionTimeoutMS = 3000, username ="", password = "")
        	print "[*] Connection established, <[UNAUTHENTICATED/EXPOSED MONGODB]> instance running....\n"
		
		print "\n[*] Use the module <[dump_info]> to retrieve MongoDB server information."
		m_client.close()


	except pymongo.errors.ConfigurationError as err:
		print "[-] Configuration error detected: potentially mismatch with MongoDB server and the PyMongo..."
                print "[-] Obsolete  MongoDB versions are inherently insecure due to vulnerabilities... let's identify the error.."
		print "[-] Error details: %s" %err

	except pymongo.errors.OperationFailure as err:
                print "[-] Operation failure: remote mongodb instance requires authentication: %s" %target
                print "[-] Error details: %s" %err

	except pymongo.errors.ConnectionFailure as err:
        	print "[-] Connection failure: %s" %target
        	print "[-] Error details: %s" %err

	except pymongo.errors.ServerSelectionTimeoutError as err:
        	print "[-] Server timeout error: %s" %target
        	print "[-] Error details: %s" %err

	return


def mongo_server_info(host,port):
        try:
                target= str(host + ":" + str(port))
                print "[*] Target : <%s>" %target
                m_client = pymongo.MongoClient(host = str(target),serverSelectionTimeoutMS = 3000, username ="", password = "")
                print "[*] Connection established, <[UNAUTHENTICATED/EXPOSED MONGODB]> instance running....\n"

                print "[*] ----------------- <[DUMPING MONGODB SERVER INFORMATION]> -----------------------\n"
                server_info = m_client.server_info()
                for key,value in server_info.iteritems():
                        print "[*] %s   :       %s" %(key,value)

                print "[*] ---------------------------------------------------------------------------------\n"
                m_client.close()

	except pymongo.errors.ConfigurationError as err:
                print "[-] Configuration error detected: potentially mismatch with MongoDB server and the PyMongo..."
                print "[-] Obsolete  MongoDB versions are inherently insecure due to vulnerabilities... let's identify the error.."
		print "[-] Error details: %s" %err

        except pymongo.errors.OperationFailure as err:
                print "[-] Operation failure: %s" %target
                print "[-] Error details: %s" %err

        except pymongo.errors.ConnectionFailure as err:
                print "[-] Connection failure: %s" %target
                print "[-] Error details: %s" %err

        except pymongo.errors.ServerSelectionTimeoutError as err:
                print "[-] Server timeout error: %s" %target
                print "[-] Error details: %s" %err

        return


def mongo_admin_check(host,port):
        try:
                target= str(host + ":" + str(port))
                print "[*] Target : <%s>" %target
                m_client = pymongo.MongoClient(host = str(target),serverSelectionTimeoutMS = 3000, username ="", password = "")
                print "[*] Connection established, trying to add user <enfilade> to the <admin> database in the target MongoDB instance ....\n"	

		enum_dbs = m_client.list_database_names()

                print "[*] Checking if the <admin> database exists on MongoDB instance: <[%s]>" %target
                for item in  enum_dbs:
			if item == "admin":
				print "[*] Admin database exists on the MongoDB instance.\n"
				print "[*] ---------------------------------------------------------------------------------"
				print "[*] Trying to add user <enfilade> with password <enfilade> to the MongoDB instance."
				m_client.admin.add_user('enfilade', 'enfilade', roles=[{'role':'readWriteAnyDatabase','role':'dbAdminAnyDatabase', 'role':'clusterAdmin','role': 'root','db':'admin'}])
				print "[*] ---------------------------------------------------------------------------------\n"
	

				print "\n[*] Verifying whether the user <enfilade> has been added or not...enumerating the <[users]>"
				db = pymongo.MongoClient(host = str(target),serverSelectionTimeoutMS = 3000, username ="", password = "")['admin']
				user_enum = db.command({'usersInfo': {'user': 'enfilade', 'db': 'admin'}})
                		
				if user_enum:
                        		print "\n[*] <[SUCCESS]> user <enfilade> has been successfully added to the MongoDB instance: [%s]>" %target
                			print user_enum
                        		print "\n[*] -------------------------------------------------------------------------"
                        		print "[*] Potential high privileges command can be executed on the MongoDB instance."
                        		print "[*] --------------------------------------------------------------------------"
                        		return
                		else:
                        		print "[*] <[FAILED]> user <enfilade> has not been successfully added to the MongoDB instance:[%s]>" %target
                        		print "[*] <[ADMIN]> operation can't be performed on the exposed MongoDB instance anonymously." 
                        		return
				db.close()

			else:
				print "[-] Admin database doesn't exist: configured database: <[%s]>, not initiating the command to add user <[enfildae], try manually... " %item
				pass

                m_client.close()


	except pymongo.errors.ConfigurationError as err:
                print "[-] Configuration error detected: potentially mismatch with MongoDB server and the PyMongo..."
                print "[-] Obsolete  MongoDB versions are inherently insecure due to vulnerabilities... let's identify the error.."
		print "[-] Error details: %s" %err

	except pymongo.errors.OperationFailure as err:
                print "[-] Operation failure: %s" %target
                print "[-] Error details: %s" %err
        
	except pymongo.errors.ConnectionFailure as err:
                print "[-] Connection failure: %s" %target
                print "[-] Error details: %s" %err

        except pymongo.errors.ServerSelectionTimeoutError as err:
                print "[-] Server timeout error: %s" %target
                print "[-] Error details: %s" %err

        return



# --------------------------------------------------------------------------------------
# Module to check for basic analysis of the MongoDB instance infected with ransomware
# ---------------------------------------------------------------------------------------

def basic_mongo_ransomware_check(host,port):
	try:
		target= str(host + ":" + str(port))
                print "[*] Target : <%s>" %target
		m_client = pymongo.MongoClient(host = str(target),serverSelectionTimeoutMS = 5000, username ="", password = "")
                print "[*] Initiating <[BASIC CHECKS]> for <[RANSOMWARE DETECTION LOGIC]>....\n"

		dbs = m_client.list_database_names()

		print "\n[*] Checking for potential traces of ransomware......"

		for item in dbs:
			if "READ_ME_TO_RECOVER_YOUR_DATA" in item or "READ_ME" in item or "RECOVER_YOUR_DATA" in item:
				print "\n[*] Database with potential ransom trace detected......"
                		print "[D] Suspicious database detected: <[%s]>\n" %item

				print "\n[*] Use the module <[intrusive_check_ransomware]> for aggresive analysis." 
			else:
				pass

		m_client.close()


	except pymongo.errors.ConfigurationError as err:
                print "[-] Configuration error detected: potentially mismatch with MongoDB server and the PyMongo..."
                print "[-] Obsolete  MongoDB versions are inherently insecure due to vulnerabilities... let's identify the error.."
		print "[-] Error details: %s" %err

	except pymongo.errors.OperationFailure as err:
                print "[-] Operation failure: %s" %target
                print "[-] Error details: %s" %err

	except pymongo.errors.ConnectionFailure as err:
		print "[-] Connection failure: %s" %target
		print "[-] Error details: %s" %err

	except pymongo.errors.ServerSelectionTimeoutError as err:
                print "[-] Server timeout error: %s" %target
                print "[-] Error details: %s" %err

	return
		



# --------------------------------------------------------------------------------------
# Module to check for detailed analysis of the MongoDB instance infected with ransomware
# ---------------------------------------------------------------------------------------

def deep_mongo_ransomware_check(host,port):
        try:
                target= str(host + ":" + str(port))
                print "[*] Target : <%s>" %target
                m_client = pymongo.MongoClient(host = str(target),serverSelectionTimeoutMS = 5000, username ="", password = "")
                print "[*] Initiating <[INTRUSIVE CHECKS]> for <[RANSOMWARE DETECTION LOGIC]>....\n"


		dbs = m_client.list_database_names()

		print "[*] Dumping the identifiers of all the databases on: <[%s]>" %target
                for item in  dbs:
                        print "[D] %s" %item

                print "\n[*] Checking for potential traces of ransomware notifications and messages......"

                for item in dbs:
                        if "READ_ME_TO_RECOVER_YOUR_DATA" in item or "READ_ME" in item or "RECOVER_YOUR_DATA" in item:
                                print "\n[*] Database with potential ransom trace detected......"
                                print "[D] Suspicious database detected: <[%s]>\n" %item

                                sus_db = m_client[item]
                                for coll in sus_db.list_collection_names():
                                        print "[C] Suspicious collection name with ransomware trace detected...... <[%s]>" %coll
                                        enum_coll = sus_db[coll]
                                      	print "[C] Suspicious collection handle: %s\n" %enum_coll

					coll_cont = enum_coll.find()
					
					print "[*] Dumping the suspicious collection records for potential <[RANSOMWARE]> messages and notifications"
					
                                        for value in coll_cont:
                                                print "[*] %s" %value


					print "\n[*] Target <[%s]> is potentially infected with <[RANSOMWARE]>" %target
			else:
				pass

                m_client.close()

	except pymongo.errors.ConfigurationError as err:
                print "[-] Configuration error detected: potentially mismatch with MongoDB server and the PyMongo..."
                print "[-] Obsolete  MongoDB versions are inherently insecure due to vulnerabilities... let's identify the error.."
		print "[-] Error details: %s" %err

 	except pymongo.errors.OperationFailure as err:
                print "[-] Operation failure: %s" %target
                print "[-] Error details: %s" %err

        except pymongo.errors.ConnectionFailure as err:
                print "[-] Connection failure: %s" %target
                print "[-] Error details: %s" %err

        except pymongo.errors.ServerSelectionTimeoutError as err:
                print "[-] Server timeout error: %s" %target
                print "[-] Error details: %s" %err

        return



# --------------------------------------------------------------------------------------
# Module to check for basic analysis of the MongoDB instance infected with meow bot
# ---------------------------------------------------------------------------------------

def deep_meow_bot_check(host,port):
        try:
                target= str(host + ":" + str(port))
                print "[*] Target : <%s>" %target
                m_client = pymongo.MongoClient(host = str(target),serverSelectionTimeoutMS = 5000, username ="", password = "")
                print "[*] Initiating <[BASIC CHECKS]> for <[MEOW BOT DETECTION LOGIC]>....\n"

                dbs = m_client.list_database_names()

                print "\n[*] Checking for potential traces of meow bot ......"

		count=0
                for item in dbs:
                        if "meow" in item:
				sus_db = m_client[item]
                                for coll in sus_db.list_collection_names():
                                        print "[C] Suspicious collection name with <meow_bot> trace detected...... <[%s]>" %coll
                                        enum_coll = sus_db[coll]
                                        print "[C] Suspicious collection handle: %s\n" %enum_coll

                                        coll_cont = enum_coll.find()

                                        print "[*] Dumping the suspicious collection records for potential <[MEOW BOT]> messages and notifications"

                                        for value in coll_cont:
                                                print "[*] %s" %value

                                        print "\n[*] Target <[%s]> is potentially infected with <[MEOW BOT]>" %target
			else:
                                pass	
	
		m_client.close()



	except pymongo.errors.ConfigurationError as err:
                print "[-] Configuration error detected: potentially mismatch with MongoDB server and the PyMongo..."
                print "[-] Obsolete  MongoDB versions are inherently insecure due to vulnerabilities... let's identify the error.."
                print "[-] Error details: %s" %err
        
	except pymongo.errors.OperationFailure as err:
                print "[-] Operation failure: %s" %target
                print "[-] Error details: %s" %err

        except pymongo.errors.ConnectionFailure as err:
                print "[-] Connection failure: %s" %target
                print "[-] Error details: %s" %err

        except pymongo.errors.ServerSelectionTimeoutError as err:
                print "[-] Server timeout error: %s" %target
                print "[-] Error details: %s" %err

        return


# --------------------------------------------------------------------------------------
# Module to check for detailed analysis of the MongoDB instance infected with meow bot
# ---------------------------------------------------------------------------------------

def basic_meow_bot_check(host,port):
        try:
                target= str(host + ":" + str(port))
                print "[*] Target : <%s>" %target
                m_client = pymongo.MongoClient(host = str(target),serverSelectionTimeoutMS = 5000, username ="", password = "")
                print "[*] Initiating <[BASIC CHECKS]> for <[MEOW BOT DETECTION LOGIC]>....\n"

                dbs = m_client.list_database_names()

                print "\n[*] Checking for potential traces of meow bot ......"

                count=0
                for item in dbs:
                        if "meow" in item:
                                print "[D] Suspicious database detected with <[meow bot]> infection: <[%s]>" %item
                                print m_client.item.command("dbstats")
                                print "\n"
                                count=count+1
                        else:
                                pass


                if count >= 2:
                        print "\n[*] [Suggestion] Use the module <[intrusive_check_meow_bot]> for aggresive analysis."
                else:
                        print "\n[*] Tool does not find any specific <[meow bot]> indicator.\n"

                m_client.close()



        except pymongo.errors.ConfigurationError as err:
                print "[-] Configuration error detected: potentially mismatch with MongoDB server and the PyMongo..."
                print "[-] Obsolete  MongoDB versions are inherently insecure due to vulnerabilities... let's identify the error.."
                print "[-] Error details: %s" %err

        except pymongo.errors.OperationFailure as err:
                print "[-] Operation failure: %s" %target
                print "[-] Error details: %s" %err

        except pymongo.errors.ConnectionFailure as err:
                print "[-] Connection failure: %s" %target
                print "[-] Error details: %s" %err

        except pymongo.errors.ServerSelectionTimeoutError as err:
                print "[-] Server timeout error: %s" %target
                print "[-] Error details: %s" %err

        return

# ---------------------------------------------------------------------------------------
# Module to map all the users in the MongoDB instance
# ---------------------------------------------------------------------------------------

def map_users(host,port):
        try:
                target= str(host + ":" + str(port))
                print "[*] Target : <%s>" %target
                m_client = pymongo.MongoClient(host = str(target),serverSelectionTimeoutMS = 5000, username ="", password = "")
                print "[*] Initiating <[ENUMERATION]> for <[MAPPING USERS TO MONGODB CONFIGURED DATABASES]>....\n"

                dbs = m_client.list_database_names()

		print "\n[*] Configured dbs on the MongoDB instance: %s" %dbs

                print "\n[*] Mapping the list of potential users ......\n"

                for item in dbs:
			print "[D] Mapped databases with configured <[USERS]>: [DBS:[%s]>]" %item
			user_handle=m_client.item.userinfo.find({})
			print user_handle
			for entry in user_handle:
				print entry
		#	for document in user_handle['users']:
    		#		print document['user'] +" "+ document['roles'][0]['role']
			print "\n"

                m_client.close()



        except pymongo.errors.ConfigurationError as err:
                print "[-] Configuration error detected: potentially mismatch with MongoDB server and the PyMongo..."
                print "[-] Obsolete  MongoDB versions are inherently insecure due to vulnerabilities... let's identify the error.."
                print "[-] Error details: %s" %err

        except pymongo.errors.OperationFailure as err:
                print "[-] Operation failure: %s" %target
                print "[-] Error details: %s" %err

        except pymongo.errors.ConnectionFailure as err:
                print "[-] Connection failure: %s" %target
                print "[-] Error details: %s" %err

        except pymongo.errors.ServerSelectionTimeoutError as err:
                print "[-] Server timeout error: %s" %target
                print "[-] Error details: %s" %err

        return



# ---------------------------------------------------------------------------------------
# Tools usage: modules support by in this version of the tool
# ---------------------------------------------------------------------------------------

def tool_usage():
	print "[-] usage: %s <mongodb host (local or remote)> <mongodb service port> <module_name>" %str(sys.argv[0])
	print "[*] modules: [verify_auth] | [dump_info] | [admin_access_verify] | [basic_check_ransomware] | [intrusive_check_ransomware]"
	print "[*]      : verify_auth --> check if MongoDB interface is <EXPOSED>"
	print "[*]	 : dump_info --> dump information of the MongoDB instance"
	print "[*] 	 : enum_users --> map active users in the MongoDB instance"
	print "[*]	 : admin_access_verify --> check if admin commands are allowed to run [adding user <enfilade> with role <root>]"
	print "[*]      : basic_check_ransomware --> check for basic <RANSOMWARE> indicators on the remote MongoDB instance"
	print "[*]      : basic_check_meow_bot --> check for basic <MEOW BOT> indicators on the remote MongoDB instance"
	print "[*]	 : intrusive_check_ransomware --> conduct detailed analysis for <RANSOMWARE> indicators/infections on the remote MongoDB instance"
	print "[*]      : intrusive_check_meow_bot --> conduct detailed analysis for <MEOW BOT> indicators/infections on the remote MongoDB instance"
	print "\n[*] example: %s 127.0.0.1 27017 ransomware\n" %str(sys.argv[0])


def main():
	banner()
	try:

		ip_address = str(sys.argv[1])
		port = int(sys.argv[2]);
		module = str(sys.argv[3]);

		module_tags = ['verify_auth','dump_info','admin_access_verify','enum_users','basic_check_ransomware','basic_check_meow_bot','intrusive_check_ransomware','intrusive_check_meow_bot']

		if module not in module_tags:
			print "\n[-] [ENFILADE> module does not exist, check for the right module and trigger execution !"
			print "[-] [ENFILADE> supported modules:", module_tags
			print "\n[-] exiting the execution stage....select the supported module and run the tool again..."
			sys.exit(0)

		mongodb_instance  = str("mongodb://" +ip_address+":"+str(port))
		print "\n"

		time.sleep(2)
		print "[#] Checking the <GEOIP> status of the MongoDB instance ......"
		from geoip import geolite2

		ip_match = geolite2.lookup(ip_address)
		if ip_match is not None:
			print "[*] MongoDB instance is located in <%s> | <%s>\n" %(ip_match.country, ip_match.timezone)
		else:
			print "[-] could not fetch the geolocation details of the ip_address: %s" %ip_address
			print "[*] continuing the execution ...... \n"
			
		print "[*] MongoDB instance identifier is constructed as: %s\n" %str(mongodb_instance)
		
		# -------------------------------------------------------------------       
                # Triggering routine to detect MongoDB infected with Ransomware
                # --------------------------------------------------------------------

		if module == "basic_check_ransomware":
			basic_mongo_ransomware_check(ip_address,port)
                        print "\n[*] Request processed successfully ! exiting !\n"
                        sys.exit(0)

		if module == "intrusive_check_ransomware":
                        deep_mongo_ransomware_check(ip_address,port)
                        print "\n[*] Request processed successfully ! exiting !\n"
                        sys.exit(0)
	

		# -----------------------------------------------------------------------       
                # Triggering routine to verify Meow Bot Infection in MongoDB instance
                # -----------------------------------------------------------------------

	  	if module == "basic_check_meow_bot":
                        basic_meow_bot_check(ip_address,port)
                        print "\n[*] Request processed successfully ! exiting !\n"
                        sys.exit(0)

                if module == "intrusive_check_meow_bot":
                        deep_meow_bot_check(ip_address,port)
                        print "\n[*] Request processed successfully ! exiting !\n"
                        sys.exit(0)

 		# -----------------------------------------------------------------------       
                # Triggering routine to verify authz/authn on the MongoDB instance
                # -----------------------------------------------------------------------


		if module == "verify_auth":
			print "[*] Validating authentication: checking if MongoDB interface is open to access..\n"
                        mongo_auth_check(ip_address,port)
			print "\n[*] Request processed successfully ! exiting !\n"
			sys.exit(0)

  		# -----------------------------------------------------------------------       
                # Triggering routine to dump information of the MongoDB instance
                # -----------------------------------------------------------------------

		if module == "dump_info":
                        print "[*] Validating authentication: checking if MongoDB interface is open to access..\n"
                        mongo_server_info(ip_address,port)
                        print "\n[*] Request processed successfully ! exiting !\n"
                        sys.exit(0)

 		# -----------------------------------------------------------------------       
                # Triggering routine to verify admin access permissions
                # -----------------------------------------------------------------------

		if module == "admin_access_verify":
			print "[*] Validating admin access: checking if MongoDB allows execution for admin commands....\n"
                        mongo_admin_check(ip_address,port)
                        print "\n[*] Request processed successfully ! exiting !\n"
                        sys.exit(0)

 		# -----------------------------------------------------------------------       
                # Triggering routine to verify authz/authn on the MongoDB instance
                # -----------------------------------------------------------------------


                if module == "enum_users":
                        print "[*] Mapping users in the exposed/open remote MongoDB instance..\n"
                        map_users(ip_address,port)
                        print "\n[*] Request processed successfully ! exiting !\n"
                        sys.exit(0)


		time.sleep(2)
		print "\n[*] Request processed successfully ! exiting !\n"

		sys.exit(0)
		
	except IndexError:
		print "\n[-] Error identified in the indexing, please check the tool usage.\n"
		tool_usage()
		sys.exit(0)

	except (TypeError, ValueError) as err:
		print "[-] Error identified as either incorrect type specification or value.\n"
		print "[E] %s\n" %err
		print "[E] Stopping the execution ..... exiting."
		sys.exit(0) 

	except KeyboardInterrupt:
		sys.exit(0)

if __name__=="__main__":
	main()
