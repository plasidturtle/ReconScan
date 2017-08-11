import os
import shutil

print(os.path.isdir("/root/oscp/"))
try:
    os.makedirs("/root/oscp/reports")
    os.makedirs("/root/oscp/exam")
    print("Creating /root/oscp/reports directory")
except:
    print("Folder already exists")

shutil.copy(("./windows-template.md"),("/root/oscp/reports/windows-template.md"))
shutil.copy(("./linux-template.md"), ("/root/oscp/reports/linux-template.md"))
print "Copied linux and windows template files into workingd Directory"
shutil.copy(("./reconscan.py"), ("/root/oscp/reconscan.py"))
print "Copied reconscan.py into working directory!"

print "Your working directory will be /root/oscp please traverse there to check out scan files"