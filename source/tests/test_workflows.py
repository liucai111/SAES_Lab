"""Known-answer, cross-implementation and observable workflow regression tests."""
import unittest
from saes.core import (SBOX,INV_SBOX,sub_nibbles,shift_rows,mix_columns,gf_mul,
                       expand_key,decryption_trace,key_schedule_trace)
from saes.service import execute
from saes.workflows import combine_keys,multiple_trace,compare_peer,independent_check,cbc_tamper_compare
from saes.ui.config import MODES


class AppendixD(unittest.TestCase):
    def test_textbook_sboxes_and_examples(self):
        self.assertEqual(SBOX,(9,4,10,11,13,1,8,5,6,2,0,3,12,14,15,7))
        self.assertEqual(INV_SBOX,(10,5,9,11,1,7,8,15,6,0,2,3,12,4,13,14))
        self.assertEqual(0xA749^0x2D55,0x8A1C)
        self.assertEqual(sub_nibbles(0x8A1C),0x604C)
        self.assertEqual(shift_rows(0x604C),0x6C40)
        self.assertEqual(mix_columns(0x6C40),0x3743)
        self.assertEqual(mix_columns(0x3743,True),0x6C40)
        self.assertEqual(gf_mul(4,12),5)

    def test_textbook_expansion(self):
        self.assertEqual(expand_key(0x2D55),(0x2D55,0xBCE9,0xA34A))
        rows=key_schedule_trace(0x2D55)
        self.assertEqual([row['hex'] for row in rows if row['step'] in ('w2','w3','w4','w5')],['BC','E9','A3','4A'])

    def test_decryption_trace_known_states(self):
        expected=['24EC','A343','A343','2B1B','F633','2EEE','2EEE','9DDD','D728']
        self.assertEqual([row['hex'] for row in decryption_trace(0x24EC,0x4AF5)],expected)
        self.assertEqual(execute('block','0x24EC','0x4AF5',decrypt=True)['trace'][-1]['hex'],'D728')


class WorkflowTests(unittest.TestCase):
    def test_join_subkeys_preserves_order(self):
        self.assertEqual(combine_keys(('0x1A2B','0011110001001101')),'0x1A2B3C4D')
        self.assertEqual(combine_keys(('0x1A2B','0x3C4D','0x5E6F')),'0x1A2B3C4D5E6F')
        for values in ((),('0x1234',),('0x1234','0x10000'),('0x1234',)*4):
            with self.assertRaises(ValueError):combine_keys(values)

    def test_multi_trace_matches_final_cipher(self):
        keys=(0x1A2B,0x3C4D,0x5E6F)
        self.assertEqual(multiple_trace(0x1234,keys[:2])[-1]['hex'],'F04D')
        self.assertEqual(multiple_trace(0x1234,keys)[-1]['hex'],'6C0F')
        self.assertEqual(multiple_trace(0x6C0F,keys,True)[-1]['hex'],'1234')
        self.assertIn('K3',multiple_trace(0x6C0F,keys,True)[1]['step'])

    def test_peer_match_and_mismatch(self):
        good=compare_peer('0xD728','0x4AF5','0x24EC')
        self.assertTrue(good['passed']);self.assertEqual(good['peer_decrypted'],'0xD728')
        bad=compare_peer('0xD728','0x4AF5','0x24ED')
        self.assertFalse(bad['passed'])
        with self.assertRaises(ValueError):compare_peer('0xD728','0x4AF5','')

    def test_independent_comparison(self):
        record=independent_check()
        self.assertEqual((record['passed'],record['count'],record['failed']),(1024,1024,0))
        self.assertIn('not an external',record['evidence_type'])
        with self.assertRaises(ValueError):independent_check(0)

    def test_cbc_xor_from_clean_baseline(self):
        args=('0x1234 0x5678 0x9ABC 0xDEF0','0x4AF5','0x1234')
        record=cbc_tamper_compare(*args)
        self.assertEqual(record['modified_ciphertext'],'0x52B1 0x9937 0xF9DC 0x64ED')
        self.assertEqual([row['modified'] for row in record['rows']],['0x1234','0x467A','0x9ABD','0xDEF0'])
        self.assertEqual(record['changed_blocks'],[2,3])
        self.assertEqual(cbc_tamper_compare(*args),record)

    def test_cbc_replacement(self):
        record=cbc_tamper_compare('0x1234 0x5678 0x9ABC 0xDEF0','0x4AF5','0x1234',kind='replace',value='0x0000')
        self.assertEqual([row['modified'] for row in record['rows']],['0x1234','0x3A90','0x038A','0xDEF0'])

    def test_cbc_iv_and_last_block_mutation(self):
        record=cbc_tamper_compare('0x1234 0x5678 0x9ABC 0xDEF0','0x4AF5','0x1234',kind='iv')
        self.assertEqual(record['changed_blocks'],[1]);self.assertEqual(record['modified_iv'],'0x1235')
        last=cbc_tamper_compare('0x1234 0x5678','0x4AF5','0x1234',block_index=2)
        self.assertEqual(last['changed_blocks'],[2])

    def test_cbc_no_op_and_validation(self):
        args=('0x1234 0x5678','0x4AF5','0x1234')
        self.assertEqual(cbc_tamper_compare(*args,value='0x0000')['changed_blocks'],[])
        for index in (0,3,True,-1):
            with self.assertRaises(ValueError):cbc_tamper_compare(*args,block_index=index)
        with self.assertRaises(ValueError):cbc_tamper_compare(*args,kind='unknown')
        with self.assertRaises(ValueError):cbc_tamper_compare(*args,value='0x10000')

    def test_mode_capabilities(self):
        self.assertEqual({code for code,mode in MODES.items() if mode.iv},{'cbc-blocks','cbc-text'})
        self.assertEqual({code for code,mode in MODES.items() if mode.padding},{'ascii'})
        self.assertEqual(MODES['double'].key_count,2);self.assertEqual(MODES['triple'].key_count,3)
