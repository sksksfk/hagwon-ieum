import test from 'node:test';
import assert from 'node:assert/strict';
import {emptyState,demoState,validateState,dueDate,feeRows,initialView} from '../core.js';

const plan=(overrides={})=>({id:'fee-1',childId:'child-a',academy:'영어',amount:200000,dueDay:31,method:'auto',startMonth:'2026-01',endMonth:'',note:'',...overrides});
const payment=(overrides={})=>({id:'pay-1',feeId:'fee-1',month:'2026-02',paidDate:'2026-02-27',dueDate:'2026-02-28',amount:190000,method:'card',academy:'영어',childId:'child-a',note:'',...overrides});
const state=()=>({...demoState(),fees:[],payments:[],prefs:{startView:'day',focus:'today',weekday:1,showNow:true}});

test('empty state includes fee collections and default preferences',()=>{
 const s=emptyState(); assert.equal(s.version,1); assert.deepEqual(s.fees,[]); assert.deepEqual(s.payments,[]);
 assert.deepEqual(s.prefs,{startView:'day',focus:'today',weekday:1,showNow:true});
});
test('v1 backups migrate missing fee fields, then reject invalid preferences',()=>{
 const s=state(); delete s.fees; delete s.payments; delete s.prefs; assert.equal(validateState(s).fees.length,0); assert.deepEqual(s.prefs,{startView:'day',focus:'today',weekday:1,showNow:true});
 for(const prefs of [{...s.prefs,weekday:7},{...s.prefs,focus:'invalid'}]) assert.throws(()=>validateState({...s,prefs}));
});
test('due dates clamp month ends, including leap February',()=>{
 assert.equal(dueDate('2026-02',31),'2026-02-28'); assert.equal(dueDate('2024-02',31),'2024-02-29'); assert.equal(dueDate('2026-04',31),'2026-04-30');
});
test('fee rows honor active months, child filter, due-date then academy order',()=>{
 const s=state(); s.fees=[plan({id:'z',academy:'Zoo',dueDay:28}),plan({id:'a',academy:'Art',dueDay:28}),plan({id:'past',startMonth:'2026-01',endMonth:'2026-01'}),plan({id:'future',startMonth:'2026-03'}),plan({id:'b',childId:'child-b',academy:'Zzz'})];
 assert.deepEqual(feeRows(s,'2026-02').map(r=>r.feeId),['a','z','b']); assert.deepEqual(feeRows(s,'2026-02','child-a').map(r=>r.feeId),['a','z']);
});
test('payment snapshot overrides edited plan; auto method alone is unpaid',()=>{
 const s=state(); s.fees=[plan({amount:250000,academy:'New name',method:'transfer'})]; s.payments=[payment()];
 const r=feeRows(s,'2026-02')[0]; assert.equal(r.paid,true); assert.equal(r.dueDate,'2026-02-28'); assert.equal(r.amount,190000); assert.equal(r.academy,'영어'); assert.equal(r.childId,'child-a'); assert.equal(r.method,'card'); assert.deepEqual(r.payment,s.payments[0]);
 s.payments=[]; s.fees=[plan({method:'auto'})]; assert.equal(feeRows(s,'2026-02')[0].paid,false);
});
test('validation rejects bad fee references, amounts, duplicate month payments, and schema',()=>{
 const s=state(); s.fees=[plan()];
 for(const p of [payment({feeId:'missing'}),payment({amount:-1}),payment({amount:1.5}),payment({paidDate:'2026-02-30'}),payment({id:'pay-2'})]) {
  const candidate={...s,payments:p.id==='pay-2'?[payment(),p]:[p]}; assert.throws(()=>validateState(candidate));
 }
 assert.throws(()=>validateState({...s,fees:[plan({amount:-1})]}));
 assert.doesNotThrow(()=>validateState({...s,payments:[payment()]}));
 assert.doesNotThrow(()=>validateState({...s,payments:[payment({amount:0})]}));
});
test('initial view handles weekdays and Sunday in the same Monday-Sunday week',()=>{
 assert.deepEqual(initialView({startView:'day',focus:'today',weekday:1,showNow:true},'2026-11-04'),{selected:'2026-11-04',layout:'day'});
 assert.deepEqual(initialView({startView:'week',focus:'weekday',weekday:1,showNow:true},'2026-11-04'),{selected:'2026-11-02',layout:'week'});
 assert.deepEqual(initialView({startView:'week',focus:'weekday',weekday:0,showNow:true},'2026-11-04'),{selected:'2026-11-08',layout:'week'});
});
