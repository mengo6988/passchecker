import requests
import hashlib
import sys

URL = "https://api.pwnedpasswords.com/range/"
res = requests.get(URL)


def request_api_data(query_char):
    # request API for data
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f"Error fetching: {res.status_code}, check API and try again."
        )
    return res


def pwned_api_check(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # converting password into hash object and then returning string of only hexadecimal digits
    first5_char, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first5_char)
    return get_pass_leaked_count(response, tail)


def get_pass_leaked_count(hashes, hash_to_check):
    # compares the response hashes with password hash to check if there are any matches
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def main(args):
    for password in sys.argv[1:]:
        count = pwned_api_check(password)
        if count:
            print(
                f"{password} was found {count} times... Change your password dum dum."
            )
        else:
            print(f"{password} not found. Good Password! Carry on")
    return "Done!"

# *if you have a text file of password, can use this
# def get_pass(args):
#     with open(str(args), mode="r") as my_file:
#         text = my_file.read()

#         password_list = []
#         for line in text.splitlines():
#             password_list.append(line)
#         return password_list


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
