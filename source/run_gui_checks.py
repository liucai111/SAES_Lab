"""Live Tk regression. A desktop is required; optional screenshots need Pillow."""
import argparse,csv,json,platform,tempfile,time,tkinter as tk
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch
from saes.ui.app import SAESApp
from saes.service import parse_word

ROOT=Path(__file__).resolve().parent
RESULTS=ROOT.parent/'test_results'


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--screenshots',action='store_true');args=parser.parse_args()
    RESULTS.mkdir(exist_ok=True)
    root=tk.Tk();app=SAESApp(root);root.update()
    records=[];screens=[]
    def check(name,fn):
        start=time.perf_counter()
        try:
            fn();root.update()
            records.append({'id':name,'status':'passed','elapsed_seconds':round(time.perf_counter()-start,6)})
        except Exception as error:
            import traceback
            records.append({'id':name,'status':'failed','error':repr(error),'traceback':traceback.format_exc()})
            print(name,repr(error),flush=True)
    def show(code):
        stage={'block':0,'ascii':2,'double':3,'triple':3,'cbc-blocks':4,'cbc-text':4}[code]
        app.select_stage(stage)
        page=app.ciphers[code]
        if stage==3:app.multiple_book.select(page)
        if stage==4:app.cbc_book.select(page)
        root.update();return page
    def fresh(code):
        page=show(code);page.load_example();root.update();return page
    def wait_attack():
        deadline=time.monotonic()+60
        while True:
            root.update()
            done=not app.attack.worker.is_alive() and str(app.attack.start_button['state'])=='normal' and app.attack.events.empty()
            if done:break
            if time.monotonic()>deadline:raise TimeoutError('Attack did not reach a terminal UI state')
            time.sleep(.01)
    def attack_page():
        app.select_stage(3);app.multiple_book.select(app.attack);root.update();return app.attack
    def shot(name):
        if not args.screenshots:return
        from PIL import ImageGrab
        root.update();root.update_idletasks()
        path=ROOT.parent/'assets'/f'{name}.png';path.parent.mkdir(exist_ok=True)
        ImageGrab.grab(bbox=(root.winfo_rootx(),root.winfo_rooty(),root.winfo_rootx()+root.winfo_width(),root.winfo_rooty()+root.winfo_height())).save(path)
        screens.append(path.name)

    def basic_fields():
        p=fresh('block')
        assert p.iv_field is None and p.padding_control is None and p.encoding_frame is None
        assert len(p.key_fields)==1 and app.selected_stage==0
        assert str(p.output.copy['state'])=='disabled'
    check('G01_stage1_only_required_fields',basic_fields)

    def basic_run():
        p=show('block');p.run_button.invoke();root.update()
        assert p.result['hex']=='0x24EC'
        assert '0010 0100 1110 1100'==p.output.value.get()
        p.output.copy.invoke();root.update();assert root.clipboard_get()=='0x24EC'
        assert not p.output.opened
        shot('stage1_basic')
        p.output.detail_button.invoke();root.update()
        assert p.output.opened and 'RotNib' in p.output.detail_text.get()
        shot('stage1_process')
    check('G02_direct_result_copy_and_process',basic_run)

    def roundtrip():
        p=show('block');p.output.handoff.invoke();root.update()
        assert p.data.get()=='0x24EC' and p.action.get()=='decrypt' and p.result is None
        p.run_button.invoke();root.update()
        assert p.result['hex']=='0xD728' and p.result['trace'][-1]['hex']=='D728'
        assert 'InvMixColumns' in p.output.detail_text.get()
    check('G03_one_click_handoff_and_inverse_trace',roundtrip)

    def stale():
        p=show('block');p.key_fields[0].set('0x4AF4');root.update()
        assert p.result is None and str(p.output.copy['state'])=='disabled'
        p.load_example();p.run();root.update()
        p.data.text.insert('end','0');root.update()
        assert p.result is None
        p.run_button.invoke();root.update()
        assert p.result is None and p.error.cget('text') and root.winfo_exists()
    check('G04_invalidate_stale_result_and_inline_error',stale)

    def persistence():
        p=fresh('block');p.data.set('0x6F6B');p.key_fields[0].set('0xA73B');p.run();root.update()
        show('ascii');show('block')
        assert p.data.get()=='0x6F6B' and p.result['hex']=='0x0738'
    check('G05_navigation_preserves_per_stage_state',persistence)

    def ascii_fields():
        p=fresh('ascii');root.update()
        assert p.padding_control.winfo_ismapped() and not p.encoding_frame.winfo_ismapped() and p.iv_field is None
        p.action.set('decrypt');root.update();assert p.encoding_frame.winfo_ismapped()
        p.action.set('encrypt');root.update();assert not p.encoding_frame.winfo_ismapped()
    check('G06_ascii_conditional_encoding_and_padding',ascii_fields)

    def ascii_raw():
        p=fresh('ascii');p.padding.set(False);p.key_fields[0].set('0xA73B');p.data.set('ok');p.run_button.invoke();root.update()
        assert p.result['hex']=='0738'
        p.output.handoff.invoke();p.run_button.invoke();root.update();assert p.result['plaintext']=='ok'
        assert not p.padding.get()
    check('G07_ascii_raw_two_byte_roundtrip',ascii_raw)

    def ascii_padded():
        p=fresh('ascii');p.data.set('ABC');p.run();root.update()
        assert p.result['hex']=='324F9645';shot('stage3_ascii')
        p.data.set('Mk+WRQ==');p.action.set('decrypt');p.encoding.set('base64');p.run();root.update()
        assert p.result['plaintext']=='ABC'
        p.action.set('encrypt');p.data.set('  A\n');p.run();p.handoff();p.run();root.update()
        assert p.result['plaintext']=='  A\n'
        p.action.set('encrypt');p.data.set('');p.run();p.handoff();p.run();root.update()
        assert p.result['plaintext']=='' and '空字符串' in p.output.secondary.cget('text')
    check('G08_ascii_padding_base64_whitespace_and_empty',ascii_padded)

    def ascii_error():
        p=fresh('ascii');p.data.set('中文');assert p.run() is None
        p.data.set('A');p.padding.set(False);assert p.run() is None
        assert p.error.cget('text') and str(p.output.handoff['state'])=='disabled'
    check('G09_ascii_rejects_non_ascii_and_odd_raw_length',ascii_error)

    def cross():
        app.select_stage(1);root.update();p=app.cross
        p.plaintext.set('0xD728');p.key.set('0x4AF5')
        p.local_button.invoke();root.update();assert '0x24EC' in p.summary.cget('text')
        p.peer.set('0x24EC');p.verify_button.invoke();root.update();assert p.records[-1]['passed']
        p.peer.set('0x24ED');p.verify_button.invoke();root.update();assert not p.records[-1]['passed']
        before=len(p.records);p.peer.set('');p.verify_button.invoke();assert len(p.records)==before
        shot('stage2_cross')
    check('G10_peer_comparison_match_mismatch_and_validation',cross)

    def reference():
        result=app.cross.run_reference()
        assert result['passed']==1024 and result['failed']==0
    check('G11_live_independent_implementation_comparison',reference)

    def multiple():
        for code,value,count in (('double','0xF04D',2),('triple','0x6C0F',3)):
            p=fresh(code);assert len(p.key_fields)==count and p.iv_field is None and p.encoding_frame is None and p.padding_control is None
            p.run_button.invoke();root.update();assert p.result['hex']==value
            shot('stage4_'+code)
            p.handoff();p.run();root.update();assert p.result['hex']=='0x1234'
    check('G12_multiple_separate_keys_and_roundtrips',multiple)

    def key_error():
        p=fresh('triple');p.key_fields[2].set('0x123');assert p.run() is None
        assert 'K3' in p.error.cget('text') and str(p.output.copy['state'])=='disabled'
    check('G13_subkey_specific_validation',key_error)

    def cbc_baseline():
        p=fresh('cbc-blocks');assert p.iv_field is not None and p.encoding_frame is None and p.padding_control is None
        assert not p.tamper_card.winfo_ismapped()
        p.run_button.invoke();root.update();assert p.result['hex']=='0x52B1 0x9936 0xF9DC 0x64ED'
        assert p.tamper_card.winfo_ismapped();shot('stage5_cbc')
        p.handoff();p.run();root.update();assert p.result['hex']=='0x1234 0x5678 0x9ABC 0xDEF0'
        assert not p.tamper_card.winfo_ismapped()
    check('G14_cbc_required_iv_and_normal_roundtrip',cbc_baseline)

    def tamper_xor():
        p=fresh('cbc-blocks');p.run();p.tamper_kind.set('翻转密文位');p.tamper_index_value.set('2');p.tamper_value.set('0x0001')
        result=p.compare_tamper();root.update()
        assert result['changed_blocks']==[2,3] and result['rows'][1]['modified']=='0x467A'
        assert len(p.tamper_table.get_children())==4
        p.canvas.yview_moveto(1);root.update();shot('stage5_tamper')
    check('G15_cbc_xor_tamper_comparison_table',tamper_xor)

    def tamper_replace_iv():
        p=show('cbc-blocks');p.tamper_kind.set('替换密文分组');root.update()
        assert p.tamper_result is None and str(p.tamper_save['state'])=='disabled'
        result=p.compare_tamper();assert result['rows'][1]['modified']=='0x3A90'
        p.tamper_kind.set('翻转IV位');root.update();assert not p.index_box.winfo_ismapped()
        result=p.compare_tamper();assert result['changed_blocks']==[1] and result['rows'][0]['modified']=='0x1235'
        p.tamper_kind.set('翻转密文位');root.update();assert p.index_box.winfo_ismapped()
        p.tamper_index_value.set('99');assert p.compare_tamper() is None
        assert not p.tamper_table.get_children()
    check('G16_cbc_replace_iv_and_invalid_index',tamper_replace_iv)

    def cbc_stale():
        p=show('cbc-blocks');p.iv_field.set('0x1235');root.update()
        assert p.result is None and p.tamper_result is None and not p.tamper_card.winfo_ismapped()
    check('G17_cbc_parameter_edit_invalidates_tamper_baseline',cbc_stale)

    def cbc_text():
        p=fresh('cbc-text');assert p.iv_field is not None and p.padding_control is None
        assert not p.encoding_frame.winfo_ismapped()
        p.run();iv=p.iv_field.get();p.handoff();root.update()
        assert p.iv_field.get()==iv and p.encoding_frame.winfo_ismapped()
        p.run();assert p.result['plaintext']=='Hello CBC!'
        p.random_iv();assert 0<=parse_word(p.iv_field.get())<=65535 and p.result is None
    check('G18_cbc_text_handoff_shared_iv_and_random_generation',cbc_text)

    def file_exports():
        p=fresh('block');p.run();root.update()
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'block.json'
            with patch('saes.ui.pages.filedialog.asksaveasfilename',return_value=str(target)):p.export()
            record=json.loads(target.read_text());assert record['result']['hex']=='0x24EC' and record['mode']=='block'
            target=Path(directory)/'cross.csv'
            with patch('saes.ui.pages.filedialog.asksaveasfilename',return_value=str(target)):app.cross.export_csv()
            with target.open(encoding='utf-8-sig') as stream:rows=list(csv.DictReader(stream))
            assert len(rows)==len(app.cross.records) and rows[0]['passed']=='True'
            p=fresh('cbc-blocks');p.run();p.compare_tamper();target=Path(directory)/'tamper.json'
            with patch('saes.ui.pages.filedialog.asksaveasfilename',return_value=str(target)):p.export_tamper()
            assert json.loads(target.read_text())['changed_blocks']==[2,3]
    check('G19_export_real_json_csv_and_tamper_records',file_exports)

    def attack_unique():
        p=attack_page();p.pairs.set('0x1234 0xF04D\n0x5678 0x031E\n0x9ABC 0xAAD1')
        p.start_button.invoke();wait_attack()
        assert p.result['candidate_count']==1 and p.result['candidates']==[(0x1A2B,0x3C4D)]
        assert p.progress['value']==131072 and len(p.table.get_children())==1
        shot('stage4_mitm')
    check('G20_live_full_space_mitm_three_pairs',attack_unique)

    def attack_single_export():
        p=attack_page();p.pairs.set('0x1234 0xF04D');p.start();wait_attack()
        assert p.result['candidate_count']==65419 and len(p.table.get_children())==100
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'all.json'
            with patch('saes.ui.pages.filedialog.asksaveasfilename',return_value=str(target)):p.export()
            record=json.loads(target.read_text());assert len(record['candidates'])==65419
    check('G21_single_pair_keeps_all_candidates_in_export',attack_single_export)

    def cancel_retry():
        p=attack_page();p.pairs.set('0x1234 0xF04D\n0x5678 0x031E\n0x9ABC 0xAAD1')
        p.start();p.cancel();wait_attack()
        assert p.result is None and '取消' in p.summary.cget('text')
        p.start();wait_attack();assert p.result['candidate_count']==1
    check('G22_attack_cancel_and_restart_without_stale_result',cancel_retry)

    def attack_edit_error():
        p=attack_page();p.pairs.set('bad pair');root.update()
        assert p.result is None and str(p.save_button['state'])=='disabled'
        p.start();assert p.result is None and not p.worker.is_alive()
        assert '请输入' in p.status.cget('text')
    check('G23_attack_edited_input_and_validation',attack_edit_error)

    def small_layout():
        p=fresh('block');p.run();root.geometry('1060x680');root.update()
        assert p._stacked is True
        p.output.toggle();root.update();p.canvas.yview_moveto(1);root.update()
        x=p.output.copy.winfo_rootx()+p.output.copy.winfo_width()
        assert x<=root.winfo_rootx()+root.winfo_width()
        root.geometry('1280x820');root.update();p.canvas.yview_moveto(0)
        assert p._stacked is False
    check('G24_small_window_stacking_and_scrollable_details',small_layout)

    app.close()
    report={'generated_at_utc':datetime.now(timezone.utc).isoformat(),'platform':platform.platform(),
            'method':'Actual Tk windows, mapped controls, button callbacks, clipboard and file-content verification',
            'checks':records,'passed':sum(r['status']=='passed' for r in records),'total':len(records),
            'screenshots':screens,'native_windows_manual':'Not executed here; verify on the submission computer',
            'external_group_test':'Not executed; peer entries in GUI regression are controlled test data'}
    (RESULTS/'gui_checks.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(report,ensure_ascii=True,indent=2))
    return 0 if report['passed']==report['total'] else 1


if __name__=='__main__':raise SystemExit(main())
