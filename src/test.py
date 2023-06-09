"""This file contains some simple test cases ensuring that the
authentication methods implemented in our system work as desired.
"""
import device
import deviceutils
import server
import serverutils


# displays results for a test function b
def result(b):
    f = 0
    if b:
        print("Success")
    else:
        print("Failed")
        f = 1
    print("")
    return f

####################
# Test functions:
####################

# Test identifier generation
# checks that a value is returned, and it is an int in the appropriate range
def test_id_gen():
    val = serverutils.generate_identifier()
    if val == None:
        return False
    if type(val) is not int:
        return False
    if val >= 0 and val <= 999999:
        return True
    return False

# Test get_identifier on empty identifier list
# or where "user" is not in identifier list
def test_empty_id():
    user = "test"
    ident = {}
    r = serverutils.get_identifier(user, ident)
    if r is None:
        return True
    return False    

# Test identifier storage
# create an identifier, save it to a identifier list, retrieve it, see if it works
def test_id_store():
    user = "test"
    nid = server.make_new_key(user)
    if user not in server.ident.keys():
        return False
    rid = server.ident[user][0]
    if type(rid) is not int:
        return False
    if rid == nid:
        return True
    return False

# Test get_keys on empty key list
# or where "user" is not in key list
def test_empty_getkeys():
    testkeys = {}
    k = serverutils.get_key("testuser", testkeys)
    if k is None:
        return True
    return False

# Test key storage
# create a key, safe it to the key list, retrieve it, see if it works
def test_getkeys():
    user = "testuser"
    key = "test"
    testkeys = {user:key}
    k = serverutils.get_key(user, testkeys)
    if k is None:
        return False
    if type(k) is not str:
        return False
    if k == key:
        return True
    return False

# Test PIN generation
# generate a pin with the device, see if check_pin on server validates it
def test_pin():
    user = "testuser"
    key = "test"
    device.key = key
    testkeys = {user:key}
    did = server.make_new_key(user)
    dpin = device.generate_pin(did)
    return serverutils.check_pin(user, dpin, server.ident, testkeys)

# Test receiving a bad pin
def test_bad_pin():
    user = "testuser"
    key = "test"
    device.key = "different_key"
    testkeys = {user:key}
    did = server.make_new_key(user)
    dpin = device.generate_pin(did)
    return not (serverutils.check_pin(user, dpin, server.ident, testkeys))

# Test for receiving a PIN for user with no/expired identifier
def test_pin_no_id():
    user = "testuser"
    key = "test"
    device.key = "different_key"
    testkeys = {user:key}
    did = server.make_new_key(user)
    server.ident.pop(user)  # remove identifier from server ident list!
    dpin = device.generate_pin(did)
    return not (serverutils.check_pin(user, dpin, server.ident, testkeys))

# Test for receiving a PIN generated with an incorrect identifier
def test_pin_bad_id():
    user = "testuser"
    key = "test"
    device.key = "different_key"
    testkeys = {user:key}
    did = server.make_new_key(user)
    did = did + 1
    dpin = device.generate_pin(did)
    return not (serverutils.check_pin(user, dpin, server.ident, testkeys))
    

####################
# Run tests:
####################
fc = 0

print("Testing identifier generation:")
fc + result(test_id_gen())

print("Testing serverutils.get_identifier on empty identifier list")
fc + result(test_empty_id())

print("Testing the storage and retrieval of an identifier in server.ident")
fc + result(test_id_store())

print("Testing serverutils.get_keys on empty key list")
fc + result(test_empty_getkeys())

print("Testing retrieval of a user key from server.keys with serverutils.get_keys")
fc + result(test_getkeys())

print("Testing PIN generation on device and validation on server")
fc + result(test_pin())

print("Testing that bad PINs are not authenticated")
fc + result(test_bad_pin())

print("Test that a PIN for a user with no/expired identifier is declined")
fc + result(test_pin_no_id())

print("Testing that a PIN generated with an incorrect identifier is declined")
fc + result(test_pin_bad_id())

print("Tests complete")
print(fc, "tests failed")