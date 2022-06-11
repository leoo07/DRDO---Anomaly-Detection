from scapy.all import *
from scapy.layers.inet import TCP, IP
import subprocess
incoming_dict = {}
outgoing_dict = {}
endpoints = {}
myip = "192.168.29.37" 
data = r'''C:\Users\praga\Documents\capture4.pcapng''' 
def getDatainKB(sz):
    return str(round(sz/1000,2))
def getDatainMB(sz):
    return str(round(sz / 1000000, 2))
def getPercentage(sz,total):
    return str(round(sz * 100 / total, 2))
def getwebsite(tempStr):
    if tempStr.__contains__("google"):
        value = "google"
    elif tempStr.__contains__("amazonaws") or tempStr.__contains__("amazon") or tempStr.__contains__("s3") or tempStr.__contains__("cloudfront"):
        value = "amazonS3"
    elif tempStr.__contains__("akamaitechnologies"):
        value = "akamaitechnologies"
    else:
        value = tempStr
    return value
def findhost(ip):
    if ip in endpoints:
        return
    proc = subprocess.Popen('nslookup ' + ip, stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    tempStr = str(out)
    value = getwebsite(tempStr)
    endpoints[str(ip)] = value
def main():
            a = rdpcap(data)
            temp = 0
            print(str(a) + "\n")
            lenth = 0
            for frame in a:
                try:
                    packet = frame[IP]
                except:
                    continue
                src = str(packet.src)
                dst = str(packet.dst)
                if packet.payload.name == 'TCP':
                    temp += 1
                    templen = frame.__len__()
                    lenth = lenth + frame.__len__()
                else:
                    continue
                if src == myip:
                    if dst in outgoing_dict:
                        outgoing_dict[dst] += templen
                    else:
                        outgoing_dict[dst] = templen
                else:
                    if src in incoming_dict:
                        incoming_dict[src] += templen
                    else:
                        incoming_dict[src] = templen
            for i in outgoing_dict.keys():
                findhost(i)
            for i in incoming_dict.keys():
                findhost(i)
            google = 0
            amazon = 0
            akamaitechnologies = 0
            other = 0
            idx = 1
            for i in outgoing_dict.keys():
                if str(endpoints[i]) == "google":
                    google += int(outgoing_dict[i])
                elif str(endpoints[i]) == "amazonS3":
                    amazon += int(outgoing_dict[i])
                elif str(endpoints[i]) == "akamaitechnologies":
                    akamaitechnologies += int(outgoing_dict[i])
                else:
                    other += int(outgoing_dict[i])
                idx += 1
            idx = 1
            for i in incoming_dict.keys():
                if str(endpoints[i]) == "google":
                    google += int(incoming_dict[i])
                elif str(endpoints[i]) == "amazonS3":
                    amazon += int(incoming_dict[i])
                elif str(endpoints[i] == "akamaitechnologies"):
                    akamaitechnologies += int(incoming_dict[i])
                else:
                    other += int(incoming_dict[i])
                idx += 1
            total = google + akamaitechnologies + amazon + other
            print("\n Total data by all the things\n")
            print("Google Firebase --- " + getDatainKB(google) + " KB ," + getDatainMB(google) + "MB ,Percentage --- " + getPercentage(google,total) +"%")
            print("\n Amazon S3 --- " + getDatainKB(amazon) + " KB ," + getDatainMB(amazon) + "MB ,Percentage --- " + getPercentage(amazon,total) +"%")
            print("\n Akamaitechnologies --- " + getDatainKB(akamaitechnologies) + " KB ," + getDatainMB(akamaitechnologies) + "MB Percentage --- " + getPercentage(akamaitechnologies,total) +"%")
            print("\n Others --- " + getDatainKB(other) + " KB ," + getDatainMB(other) + " MB ,Percentage --- " + getPercentage(other,total) +"%")
            print("\nOverall Data " + getDatainKB(total) + " KB ," + getDatainMB(total) )
if __name__ == '__main__':
    main()