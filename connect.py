# Python on server side to get connect dialplans on freeswitch
import os
from sqlite3 import enable_shared_cache
#run command "list_users"
import ESL
# Make log file.
#get list of user from freeswitch
def get_list_users():
    #run command "list_users"
    test = con.api("list_users as json")

    #get list of user from freeswitch
    #list_users = con.get_data()
    #print(list_users)
    #return list_users
    return test.getBody()
def check_ban(ban):
    count = 0
    print ("Adding network to ban file - " + ban)
    log_file = open("Log/info_script.log", "a")
    log_file.write("Adding network to ban - " +ban +"\n")
    log_file.close()    
    with open("ban_ip.txt", "a") as myfile:
        myfile.write(ban + "\n") 
    with open("ban_ip.txt", "r") as myfile:
    #check if var ban is in ban_ip more than 3 times
        lines = myfile.readlines()
        for line in lines:
            #check if line match ban
            if line == (ban + "\n"):
                #print how many times this line appear in ban_ip.txt
                count += 1
                if count > 2:
                    #This line appears more than 3 times in ban_ip.txt    
                    print ("This line appears more than 3 times in ban_ip.txt")
                    print("Ban ip")
                    os.system("fail2ban-client set freeswitch banip " + ban)
                myfile.close()
    return count

con = ESL.ESLconnection("127.0.0.1", "8021", "ClueCon")

if con.connected():
    countfile = 0
    con.events('plain', 'all')
    x = get_list_users()
    print(x)
    while 1:
        #check if Log/info_script.log is larger than 100000 bytes if yes create new file
        #check if file exist
        if os.path.isfile("Log/info_script.log"):
            if os.path.getsize("Log/info_script.log") > 100000000:
                #create new file with date in name and number of file in name
                os.system("mv Log/info_script.log Log/info_script_" + str(countfile) + ".log")
                countfile += 1
                #create new file Log/info_script.log
                os.system("touch Log/info_script.log")
        e = con.recvEvent()
        if e:
            #print serialize to log file
            log_file = open("Log/info_script.log", "a")
            log_file.write(e.serialize())
            log_file.close()

            # check if user being used in from-user is in list_users
            if e.getHeader("from-user") != None:
                if e.getHeader("Event-Subclass") != "sofia::pre_register":
                    print ("This has from user first")
                    if x.find(e.getHeader('from-user')) != -1:
                        print("User is in list_users")
                        print ("Checking Auth")
                        if e.getHeader("auth-result") == "RENEWED":
                            print ("Auth is valid, user authenticated, removing ip from ban and allowing access")
                            # remove ip from ban
                            os.system("fail2ban-client unban " + e.getHeader("network-ip"))
                            # remove lines with network ip from ban_ip.txt
                            os.system("sed -i '/" + e.getHeader("network-ip") + "/d' ban_ip.txt")
                            print ("unbanned ip")
                        elif e.getHeader("auth-result") == "FORBIDDEN":
                            print ("Auth is invalid, user not authenticated, banning ip")
                            # ban ip
                            ban = e.getHeader("network-ip")            
                            check_ban(ban)
                        else:
                            if e.getHeader("Event-Subclass") == "sofia::register":
                                print ("User is authenticted leave him alone\n")
                    else:
                        print("User is not in list_users so it's not valid")
                        print (e.serialize())
                        print ("Adding network to ban file")
                        ban = e.getHeader("network-ip")
                        print ("Adding network to ban file")
                        ban = e.getHeader("network-ip")            
                        check_ban(ban)
                elif e.getHeader("Event-Subclass") == "sofia::register_attempt":
                    if x.find(e.getHeader('to-user')) != -1:
                        print("User is in list_users")
                        print ("Checking Auth")
                        if e.getHeader("auth-result") == "RENEWED":
                            print ("Auth is valid, user authenticated, removing ip from ban and allowing access")
                            # remove ip from ban
                            os.system("fail2ban-client unban " + e.getHeader("network-ip"))
                            # remove lines with network ip from ban_ip.txt
                            os.system("sed -i '/" + e.getHeader("network-ip") + "/d' ban_ip.txt")
                            print ("unbanned ip")
                        elif e.getHeader("auth-result") == "FORBIDDEN":
                            print ("Auth is invalid, user not authenticated, banning ip")
                            # ban ip
                            ban = e.getHeader("network-ip")            
                            check_ban(ban)
                        else:
                            if e.getHeader("Event-Subclass") == "sofia::register":
                                print ("Valid Atempt\n")
                
                else:
                    if e.getHeader("Event-Subclass") == "sofia::pre_register":
                        #skip verification
                        log_file = open("Log/info_script.log", "a")
                        log_file.write("Skip verification Pre_Register\n")
                        log_file.close()
                        print ("Skipping verification BECOUSE OF PRE_REGISTER") 
                    else:    
                        #if user is not in list_users ban after 3 failed login
                        if (e.getHeader("registration-type") == "REGISTER"):
                                if e.getHeader("to-user") != None:
                                    if x.find(e.getHeader('to-user')) != -1:
                                        print("User is in list_users")
                                        log_file = open("Log/info_script.log", "a")
                                        log_file.write("User exists\n")
                                        log_file.write("Checking Register\n")
                                        log_file.close()
                                        #print (e.serialize())
                                        print ("Checking Regisiter")
                                        if e.getHeader("Event-Subclass") == "sofia::register_failure":
                                            log_file = open("Log/info_script.log", "a")
                                            log_file.write("Register failed.\n")
                                            log_file.close()
                                            print ("Register failed")
                                            #add network to ban file
                                            print ("Adding network to ban file")
                                            ban = e.getHeader("network-ip")            
                                            check_ban(ban)
                        else:
                            print ("This is not a register") 
                            log_file = open("Log/info_script.log", "a")
                            log_file.write("This user is not registed\n")
                            log_file.close() 
                                    
            else:
                #Check if is a call
                print("jump")
print ("Not connected")
con.disconnect()
