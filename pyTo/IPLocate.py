#!/usr/bin/python
#coding:utf-8
#Filename:IPLocate.py
#The Program Is Used To Locate IP.

import re
import socket
import struct

_unpack_S = lambda s: struct.unpack("12s", s)#12s is len=12's string
_unpack_L = lambda l: struct.unpack("<L", l)#<l is <long类型的长度


class IP(object):
    def __init__(self, ):
        self.offset_addr = 0
        self.offset_owner = 0
        self.offset_info = None
        self.ip_re = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')#匹配的应该是ip地址，255,255,255,255

    '''载入dat文件方法'''
    def load_dat(self, fname):
        '''Load Dat File To Memory'''
        try:
            f = open(fname, "rb")#读取文件
            finfo = f.readlines()#打开文件-read读取所有 readline读取一行 readlines读取几行成列表
            '''由于文件比较大，测试的时候用readline比较快一点'''
            '''dat文件中 提取数据 存入列表'''
            self.offset_info = finfo[8:]
            self.offset_addr, = _unpack_L(finfo[0:4])
            self.offset_owner, = _unpack_L(finfo[4:8])
            f.close()#关闭文件
        except:
            print "Loda File Fail."
            exit(0)

    def locate_ip(self, ip):
        '''Locate IP'''
        if self.ip_re.match(ip):#首先用正则匹配ip 看输入的ip是否符合上面的正则
            nip = socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip)))[0])#将输入的ip转化为32位二进制格式
            #这个dat文件是二进制的  需要将输入的string转化一下
            #具体查询socket.iner_aton方法
        else:
            return ['Error IP']

        '''此处貌似用二分法对offset_addr列表进行遍历 找出与输入ip相同的字段'''
        record_min = 0
        record_max = self.offset_addr / 108 - 1
        record_mid = (record_min + record_max) / 2
        while record_max - record_min >= 0:
            #获得dat中的最小ip和最大ip
            minip, = _unpack_L(self.offset_info[record_mid * 108: record_mid * 108 + 4])
            maxip, = _unpack_L(self.offset_info[record_mid * 108 + 4: record_mid * 108 + 8])
            if nip < minip:#如果ip比最小ip小
                record_max = record_mid - 1#游标退一位
            elif (nip == minip) or (nip > minip and nip < maxip) or (nip == maxip):#如果找到对应ip
                #开始提取数据 并返回
                addr_begin, = _unpack_L(self.offset_info[record_mid * 108 + 8: record_mid * 108 + 12])
                addr_length, = _unpack_L(self.offset_info[record_mid * 108 + 12: record_mid * 108 + 16])
                owner_begin, = _unpack_L(self.offset_info[record_mid * 108 + 16: record_mid * 108 + 20])
                owner_length, = _unpack_L(self.offset_info[record_mid * 108 + 20: record_mid * 108 + 24])
                bd_lon, = _unpack_S(self.offset_info[record_mid * 108 + 24: record_mid * 108 + 36])#09 坐标系经度 坐标系经度
                bd_lat, = _unpack_S(self.offset_info[record_mid * 108 + 36: record_mid * 108 + 48])#09 坐标系纬度 坐标系纬度
                wgs_lon, = _unpack_S(self.offset_info[record_mid * 108 + 48: record_mid * 108 + 60])#S09 坐标系经度 坐标系经度
                wgs_lat, = _unpack_S(self.offset_info[record_mid * 108 + 60: record_mid * 108 + 72])#WGS09 坐标系纬度 坐标系纬度
                radius, = _unpack_S(self.offset_info[record_mid * 108 + 72: record_mid * 108 + 84])#区域半径
                scene, = _unpack_S(self.offset_info[record_mid * 108 + 84: record_mid * 108 + 96])#应用场景
                accuracy, = _unpack_S(self.offset_info[record_mid * 108 + 96: record_mid * 108 + 108])#地理位置精度 地理位置精度
                addr = self.offset_info[addr_begin:addr_begin+addr_length].split("|")#各级地址 亚洲-中国-山西-太原-万柏林。。7个字段
                owner = self.offset_info[owner_begin:owner_begin+owner_length]#拥有者名 拥有者名
                '''返回信息'''
                return [str(minip), str(maxip), addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], bd_lon, bd_lat, wgs_lon, wgs_lat, radius, scene, accuracy, owner]
            elif nip > maxip:#如果ip比最大ip大
                record_min = record_mid + 1#游标+1
            else:
                print "Error Case"
            record_mid = (record_min + record_max) / 2
        return ['Not Found.']
