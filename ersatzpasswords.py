import strgen
import hashlib
import getpass

# Function to hash passwords, using SHA256
def hash_password(u,s):
	count = 0
	hash_object = hashlib.sha256(s.encode())
	hex_dig = hash_object.hexdigest()
	
	return hex_dig

# Function to write new user credentials to file	
def write_op_to_file(wv):
	f = open("etc_password.txt","a+")
	f.write(wv)
	f.close()
# Function to write ersatz password to a file
def write_ep_to_file(wev):
	
	f = open("etc_ezpassword.txt","a+")
	f.write(wev)
	f.close()

# Function to avail user secret to generate the ersatzpassword
def e_input():
	e_input_c = raw_input("\nChoose a 4 character pin:")
	return e_input_c

# Function to create the ersatzpassword
# Techniques used : Total password replacement and User input (implicit and explicit)
	
def create_ersatz_passwords(u,p):
	e_input_character = e_input()
	while len(e_input_character)!= 4:
		print " \n Invalid 4 digit pin, please follow the standards and choose again"
		e_input_character = e_input()
	cipher = " "
	for i in p:
		cipher = cipher + chr(ord(i) + 2)
	# Final Ersatz password
	cipher = cipher + e_input_character
	
	return cipher
		
	
# Registration for a new user	
def new_user():
	user_name = raw_input(" Enter a new user name\n")
	password = getpass.getpass("\n Create a password \n Requirements - 12 characters long : \n ")
	confirm_password = getpass.getpass(" \n Confirm your password : ")
	if len(password) != 12 or password != confirm_password:
		print " \nInvalid password"
		return 100
	else:
		# Case to handle successfull password generation
		# Generate salt
		salt = strgen.StringGenerator("[\d\w]{4}").render()
		salted_password = password + str(salt)
		hon_salt_password = hash_password(user_name,salted_password)
		write_value = user_name + ":" + str(salt) + "=" + hon_salt_password + "\n"
		write_op_to_file(write_value)
		
		# Now create Ersatz passwords

		ersatz_password = create_ersatz_passwords(user_name,password)
		length = len(ersatz_password)
		ersatz_password = ersatz_password[1:(length - 1)]
		new_salt = strgen.StringGenerator("[\d\w]{4}").render()
		salted_e_password = ersatz_password + new_salt
		
		hon_salt_epassword = hash_password(user_name, str(salted_e_password))
		
		
		write_ep_value = user_name + ":" + str(new_salt) + "=" + hon_salt_epassword + "\n"
		write_ep_to_file(write_ep_value)

# User authentication		
def check_for_login(u,p):
	f = open("etc_password.txt",'r+')
	#try:
	while(1):
	
		line = f.readline()
		a,b = line.split(":")
		if a == u:
			salt,hashed_password = b.split("=")
			break
		
	salted_p = p + salt
	hon_salted_p = hash_password(u, salted_p)

	# [0:64] done to remove \n character	
	if hon_salted_p == hashed_password[0:64]:

		# Case 1 - Successful
		print "\n USER IS AUTHENTICATED"
	else:
		fo = open("etc_ezpassword.txt","r+")
		while(1):
		
			line_ep = fo.readline()
			fe,g = line_ep.split(":")
			
			if fe == u:
				salt_ep,hashed_password_ep = g.split("=")
				break
		
		salted_ep = p + salt_ep
		salted_ep = salted_ep[0:15] + salted_ep[16:(len(salted_ep))]
		hon_salted_ep = hash_password(u,salted_ep)
		
		# Case 2 - Ersatz Password Login
		if hon_salted_ep == hashed_password_ep[0:64]:
			print "\n ALARM RAISED, SYSTEM PASSWORD FILE COMPROMISED, ERSATZ PASSWORD USED BY AN ATTACKER \n"
		# Case 3 - Wrong Password
		else:
			print " WRONG PASSWORD - CASE 3 (ERROR) "
			
	#except:
		#print " \n User doesn't exist "	
		
		
def existing_user():
	# Need to perform 3 checks, successfull, ersatz login and error login
	user_name = raw_input(" Enter your name\n")
	password = getpass.getpass("\n Enter your password :")
	result = check_for_login(user_name, password)


def main():
	input_user = raw_input("\nEnter the mode of operation \n Enter 1 for creating an account (storing passwords) \n Enter 2 for an existing user (retrieve a password)\n")
	if input_user == "1":
		new_user()
	elif input_user == "2":
		existing_user()
	else:
		print "\nUser provided invalid input"



if __name__ == "__main__":
	main()
