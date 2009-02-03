import os
import random
import string
import sys
import shutil
import threading

def assert_(val, error):
    if not val:
        raise AssertionError(error)

dirs = [sys.argv[1]] + [''.join(random.sample(string.letters, 10)) for i in xrange(5)]
filenames = [''.join(random.sample(string.letters, 10)) for i in xrange(5)]
filedata = [''.join(random.sample(string.letters, 10)) for i in xrange(5)]
files = dict(zip(filenames, filedata))
fulldirs = [os.path.join(*dirs[0:i]) for i in xrange(2, len(dirs)+1)]
for dir in fulldirs:
    print "mkdir", dir
    os.mkdir(dir)
    for filename, filedata in files.iteritems():
        file_path = os.path.join(dir, filename)
        fp = open(file_path, 'wb')
        fp.write(filedata)
        fp.close()
        fp = open(file_path, 'wb')
        fp.write(filedata)
        fp.close()
        fp = open(file_path, 'wb')
        fp.write(filedata)
        fp.close()
for dir in fulldirs[::-1]:
    print "listdir", dir
    file_list = os.listdir(dir)
    for filename, filedata in files.iteritems():
        assert_(filename in file_list, '%s not in dir' % filename)
        file_path = os.path.join(dir, filename)
        fp = open(file_path, 'rb')
        assert_(fp.read() == filedata, 'filedata not correct')
        fp.close()
        fp = open(file_path, 'rb')
        assert_(fp.read() == filedata, 'filedata not correct')
        fp.close()
        fp = open(file_path, 'rb')
        assert_(fp.read() == filedata, 'filedata not correct')
        fp.close()
print "rmtree", fulldirs[0]
shutil.rmtree(fulldirs[0])


