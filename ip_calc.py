rack = input("Rack number: ")
col = rack[1].upper()
map={'A':1,'B':2,'C':3,'D':4,'E':5,'F':6,'G':7,'H':8}
col = map.get(col, 0)
f=int(str(rack[0])+str(col))-(4*int(rack[0])) - 6
g = f*8


print(f"ISP 1 Edge router IP block: 172.17.9.{4*f}/30")
print(f"ISP 1 Public IP block: 203.149.{210 + (g//256)}.{g % 256}/29")
print(f"ISP 2 Edge router IP block: 172.17.10.{4*f}/30")
print(f"ISP 2 Public IP block: 129.126.{142 + (g//256)}.{g % 256}/29")