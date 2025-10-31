from Evtx.Evtx import Evtx
import re, csv

evtx_path = "Security.evtx"
rows = []
with Evtx(evtx_path) as log:
    for record in log.records():
        xml = record.xml()
        if "<EventID>4624</EventID>" in xml:
            # find Data Name fields
            def find(name):
                m = re.search(rf'<Data Name="{re.escape(name)}">([^<]*)</Data>', xml)
                return m.group(1) if m else ""
            rows.append({
                "Time": re.search(r'<TimeCreated SystemTime="([^"]+)"', xml).group(1) if re.search(r'<TimeCreated SystemTime="([^"]+)"', xml) else "",
                "User": find("TargetUserName"),
                "LogonType": find("LogonType"),
                "Workstation": find("WorkstationName"),
                "IpAddress": find("IpAddress")
            })

# print unique workstation names
ws = {}
for r in rows:
    w = r["Workstation"] or "<EMPTY>"
    ws[w] = ws.get(w,0) + 1

print("Unique WorkstationNames and counts:")
for k,v in sorted(ws.items(), key=lambda x:-x[1]):
    print(f"{k} : {v}")

# save all rows
with open("4624_events.csv","w",newline="",encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["Time","User","LogonType","Workstation","IpAddress"])
    writer.writeheader()
    writer.writerows(rows)

print("Wrote 4624_events.csv")
