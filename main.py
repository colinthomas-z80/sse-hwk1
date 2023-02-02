import sqlite3
import json
import glob
import uuid
import os
import sys
import xml.etree.ElementTree as xml
import packaging.version


def load_db():
    os.system("rm ./db.sqlite")

    con = sqlite3.connect("db.sqlite")
    cur = con.cursor()

    cur.execute("CREATE TABLE cve(id, severity)")
    cur.execute("CREATE TABLE packages(uuid, cve, manufacture, prodid, version, startversion, endversion, mode)")

    for file in glob.glob("./nvdcve*"):
        f = open(file, "r")
        jcve_document = json.load(f)
        for i in jcve_document["CVE_Items"]:
            jcve = i["cve"]
            id = jcve["CVE_data_meta"]["ID"]
            jconf = i["configurations"]
            for j in jconf["nodes"]:
                for z in j["cpe_match"]:
                    uri = json.dumps(z["cpe23Uri"])
                    sect = uri.split(":")
                    manufacture = sect[3].replace("'", "_")
                    product = sect[4].replace("'", "_")
                    version = sect[5].replace("'", "_")
                    startversion = "*"
                    endversion = "*"
                    mode = ""
                    if version == "*":
                        keys = z.keys()
                        if "versionStartExcluding" in keys:
                            startversion = json.dumps(z["versionStartExcluding"])
                            mode = "E"
                        if "versionStartIncluding" in keys:
                            startversion = json.dumps(z["versionStartIncluding"])
                            mode = "I"
                        if "versionEndExcluding" in keys:
                            endversion = json.dumps(z["versionEndExcluding"])
                            mode += "E"
                        if "versionEndIncluding" in keys:
                            endversion = json.dumps(z["versionEndIncluding"]) 
                            mode += "I"
                    identifier = uuid.uuid4()
                    cur.execute("INSERT INTO packages VALUES ('{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}')".format(identifier, id, manufacture, product, version, startversion, endversion, mode))
            jimpact = i["impact"]
            if len(jimpact) >= 2:
                severity = json.dumps(jimpact["baseMetricV2"]["severity"])
            else:
                severity = "NOT AVAIL"

            cur.execute("INSERT INTO cve VALUES ('{0}', '{1}')".format(id, severity))

    con.commit()
    con.close()
    


def parse_xml(file):
    detected = False
    con = sqlite3.connect("db.sqlite")
    cur = con.cursor()

    tree = xml.parse(file)
    root = tree.getroot()
    for dep in root.findall("*/{http://maven.apache.org/POM/4.0.0}dependency"):
        version = {}
        for gid in dep.findall("{http://maven.apache.org/POM/4.0.0}groupId"):
            groupId = gid.text
        for aid in dep.findall("{http://maven.apache.org/POM/4.0.0}artifactId"):
            artifactId = aid.text
        for ver in dep.findall("{http://maven.apache.org/POM/4.0.0}version"):
            version = ver.text

        

        res = cur.execute("SELECT * FROM packages WHERE prodid LIKE '{0}'".format(artifactId))
        res = res.fetchall()

        for result in res:
            if len(result) > 0:
                cversion = result[4]
                versionstring=""
                if cversion != "*":
                    if packaging.version.parse(cversion) <= packaging.version.parse(version):
                        continue
                else:
                    sversion = result[5].strip("'\"")
                    eversion = result[6].strip("'\"")
                    mode = result[7].strip("'\"")
                    try:
                        if mode == "I":
                            versionstring = "<= {0}".format(eversion)
                            if packaging.version.parse(eversion) <= packaging.version.parse(version):
                                continue
                        if mode == "E":
                            versionstring = "< {0}".format(eversion)
                            if packaging.version.parse(eversion) < packaging.version.parse(version):
                                continue
                        if mode == "IE":
                            versionstring = ">= {0} < {1}".format(sversion,eversion)
                            if packaging.version.parse(eversion) <= packaging.version.parse(version) > packaging.version.parse(sversion):
                                continue
                        if mode == "EI":
                            versionstring = "> {0} <= {1}".format(sversion,eversion)
                            if packaging.version.parse(eversion) < packaging.version.parse(version) >= packaging.version.parse(sversion):
                                continue
                        if mode == "II":
                            versionstring = ">= {0} <= {1}".format(sversion,eversion)
                            if packaging.version.parse(eversion) <= packaging.version.parse(version) >= packaging.version.parse(sversion):
                                continue
                        if mode == "EE":
                            versionstring = "> {0} < {1}".format(sversion,eversion)
                            if packaging.version.parse(eversion) < packaging.version.parse(version) > packaging.version.parse(sversion):
                                continue
            
                    except:
                        continue

                # print(groupId)
                # print(artifactId)
                # print(version)
                # print(result)

                print("Vulnerabilities Detected:")
                print()
                print("Dependency: {0} - {1}".format(groupId, artifactId))
                print("Version(s): {0}".format(versionstring))
                sev = cur.execute("SELECT severity FROM cve WHERE id='{0}'".format(result[1]))
                print("Vulnerabilities: \n\t{0} ( {1} )".format(result[1], sev.fetchone()[0].strip("\"")))
                print()
                detected = True

    if detected == False:
        print("No Vulnerabilities Detected")

        
       
def main():
    if len(sys.argv) != 3:
        print("Incorrect usage. \n\t python main.py [doAll | detectOnly] /path/to/pom.xml")

    com = sys.argv[1]

    with open("result.txt", "w") as sys.stdout:
        if com == "detectOnly":
            parse_xml(sys.argv[2])
        elif com == "doAll":
            load_db()
            parse_xml(sys.argv[2])
        else:
            print("Unrecognized Command")
    
    


if __name__ == "__main__":
    main()

            
    



