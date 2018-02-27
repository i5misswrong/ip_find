import os


try:
    f=open(os.pardir+'/pyTo/ip_dat.dat',"rb")

    f_l=f.readline()
    print (type(f_l))
    print ('success')
except:
    print ('fail')