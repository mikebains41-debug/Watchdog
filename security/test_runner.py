import subprocess,json,datetime,os,sys

TESTS=[
    ("test1_covert_channel.py","Covert Cross-GPU Side Channel"),
    ("test2_financial_dos.py","Financial DoS"),
    ("test3_hardware_fingerprint.py","Hardware Fingerprint"),
    ("test4_mig_leakage.py","MIG Partition Leakage"),
    ("test5_recovery_attempts.py","Recovery Attempts"),
    ("test6_thermal_acoustic.py","Thermal Acoustic Side Effects"),
    ("test7_clock_lock.py","Memory Clock Lock After Shift"),
]

results=[]
start_all=datetime.datetime.utcnow().isoformat()

for script,name in TESTS:
    path=os.path.join(os.path.dirname(__file__),script)
    print(f"\n=== Running {name} ===",flush=True)
    start=datetime.datetime.utcnow().isoformat()
    try:
        r=subprocess.run(["python3",path],capture_output=True,text=True,timeout=1800)
        status="PASS" if r.returncode==0 else "FAIL"
        output=r.stdout[-2000:] if r.stdout else ""
        error=r.stderr[-500:] if r.stderr else ""
    except subprocess.TimeoutExpired:
        status="TIMEOUT"
        output=""
        error="Test exceeded 30 minute timeout"
    except Exception as e:
        status="ERROR"
        output=""
        error=str(e)
    results.append({"test":name,"script":script,"status":status,"started_at":start,"output":output,"error":error})
    print(f"{name}: {status}",flush=True)

report={"run_at":start_all,"total":len(TESTS),"passed":sum(1 for r in results if r["status"]=="PASS"),"failed":sum(1 for r in results if r["status"]=="FAIL"),"results":results}
with open("phase2_test_report.json","w") as f:
    json.dump(report,f,indent=2)
print(f"\nReport saved to phase2_test_report.json",flush=True)
print(f"Passed: {report['passed']}/{report['total']}", flush=True)
