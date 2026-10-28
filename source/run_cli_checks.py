"""Reproduce documented CLI samples and retain stdout/stderr plus return codes."""
import json,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent


def main():
    cases=[
      ('block_encrypt',['block','--data','0xD728','--key','0x4AF5'],'hex','0x24EC'),
      ('block_decrypt',['block','--data','0x24EC','--key','0x4AF5','--decrypt'],'hex','0xD728'),
      ('all_zero',['block','--data','0x0000','--key','0x0000'],'hex','0x071E'),
      ('all_one',['block','--data','0xFFFF','--key','0xFFFF'],'hex','0x5343'),
      ('ascii_raw_encrypt',['ascii','--data','ok','--key','0xA73B','--no-padding'],'hex','0738'),
      ('ascii_raw_decrypt',['ascii','--data','0738','--key','0xA73B','--no-padding','--decrypt'],'plaintext','ok'),
      ('ascii_padded_encrypt',['ascii','--data','ABC','--key','0x4AF5'],'hex','324F9645'),
      ('ascii_padded_decrypt',['ascii','--data','324F9645','--key','0x4AF5','--decrypt'],'plaintext','ABC'),
      ('ascii_base64',['ascii','--data','Mk+WRQ==','--key','0x4AF5','--decrypt','--encoding','base64'],'plaintext','ABC'),
      ('double_encrypt',['double','--data','0x1234','--key','0x1A2B3C4D'],'hex','0xF04D'),
      ('double_decrypt',['double','--data','0xF04D','--key','0x1A2B3C4D','--decrypt'],'hex','0x1234'),
      ('triple_encrypt',['triple','--data','0x1234','--key','0x1A2B3C4D5E6F'],'hex','0x6C0F'),
      ('triple_decrypt',['triple','--data','0x6C0F','--key','0x1A2B3C4D5E6F','--decrypt'],'hex','0x1234'),
      ('cbc_encrypt',['cbc-blocks','--data','0x1234 0x5678 0x9ABC 0xDEF0','--key','0x4AF5','--iv','0x1234'],'hex','0x52B1 0x9936 0xF9DC 0x64ED'),
      ('cbc_decrypt',['cbc-blocks','--data','0x52B1 0x9936 0xF9DC 0x64ED','--key','0x4AF5','--iv','0x1234','--decrypt'],'hex','0x1234 0x5678 0x9ABC 0xDEF0'),
      ('cbc_bit_flip',['cbc-blocks','--data','0x52B1 0x9937 0xF9DC 0x64ED','--key','0x4AF5','--iv','0x1234','--decrypt'],'hex','0x1234 0x467A 0x9ABD 0xDEF0'),
      ('cbc_replace',['cbc-blocks','--data','0x52B1 0x0000 0xF9DC 0x64ED','--key','0x4AF5','--iv','0x1234','--decrypt'],'hex','0x1234 0x3A90 0x038A 0xDEF0'),
      ('cbc_iv_flip',['cbc-blocks','--data','0x52B1 0x9936 0xF9DC 0x64ED','--key','0x4AF5','--iv','0x1235','--decrypt'],'hex','0x1235 0x5678 0x9ABC 0xDEF0'),
      ('full_mitm',['mitm','--pairs-file','pairs.txt'],'candidate_count',1),
      ('reject_short_block',['block','--data','1010','--key','0x4AF5'],None,None),
      ('reject_odd_raw_ascii',['ascii','--data','A','--key','0x4AF5','--no-padding'],None,None),
      ('reject_short_iv',['cbc-blocks','--data','0x1234','--key','0x4AF5','--iv','0x123'],None,None),
      ('reject_long_key',['block','--data','0x1234','--key','0x10000'],None,None),
    ]
    records=[]
    for name,args,field,expected in cases:
        started=time.perf_counter()
        result=subprocess.run([sys.executable,'-m','saes',*args],cwd=ROOT,capture_output=True,text=True,encoding='utf-8')
        if field is None:passed=result.returncode==2
        else:
            try:passed=result.returncode==0 and json.loads(result.stdout)[field]==expected
            except (ValueError,KeyError):passed=False
        records.append({'id':name,'args':args,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'expected':expected,
                        'passed':passed,'elapsed_seconds':time.perf_counter()-started})
    report={'generated_at_utc':datetime.now(timezone.utc).isoformat(),'passed':sum(r['passed'] for r in records),'total':len(records),'cases':records}
    target=ROOT.parent/'test_results/cli_checks.json';target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(f"CLI {report['passed']}/{report['total']} passed")
    return 0 if report['passed']==report['total'] else 1


if __name__=='__main__':raise SystemExit(main())
