import re

global cnt
cnt = 0


def substitude(ori):
    cast_method = 'reinterpret_cast'
    matchObj = re.match(r'(.*) (.*) = \((.*)\)data;', ori, re.M | re.I)
    if matchObj:
        i = 0
        while ori[i] == ' ':
            i += 1
        new_line = \
            matchObj.group(1) + ' ' + matchObj.group(2) + ' =\n' + ' ' * (i + 4) + cast_method + '<' + matchObj.group(
                3) + '>(data);\n'
        global cnt
        cnt += 1
        return new_line
    return ori


def main():
    file_name = 'bundle_mgr.cpp'
    test_str = \
        "            AsyncApplicationInfoCallbackInfo* asyncCallbackInfo = (AsyncApplicationInfoCallbackInfo*)data;"
    print(substitude(test_str))
    new_file = open("modified_" + file_name, 'w')
    file = open(file_name, 'r')
    line = file.readline()
    while line:
        new_file.write(substitude(line))
        line = file.readline()
    print(cnt)


main()
