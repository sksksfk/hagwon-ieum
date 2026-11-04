import {test} from 'node:test';
import assert from 'node:assert/strict';
import {demoState,applyScheduleChange,privacyProjection,validateState,onDate} from '../core.js';

const changed=(item,overrides={})=>({...item,...overrides});

test('weekday edit splits sample English schedule and changes only Wednesday',()=>{
 const state=demoState(), before=structuredClone(state), source=state.schedules.find(s=>s.id==='s2');
 const next=applyScheduleChange(state,changed(source,{start:'14:30',end:'15:30',vehicle:'영어 9호차'}),'s2','weekday','2026-11-04');
 validateState(next);
 const mon=next.schedules.find(s=>s.id==='s2'), wed=next.schedules.find(s=>s.id!=='s2'&&s.childId==='child-a'&&s.title==='영어 학원'&&s.days.includes(3));
 assert.deepEqual(mon.days,[1,5]); assert.equal(mon.start,'14:00'); assert.equal(mon.vehicle,'영어학원 1호차');
 assert.deepEqual(wed.days,[3]); assert.equal(wed.start,'14:30'); assert.equal(wed.vehicle,'영어 9호차');
 assert.equal(onDate(next,'2026-11-04','child-a').find(x=>x.title==='영어 학원').start,'14:30');
 assert.deepEqual(next.schedules.find(s=>s.id==='s6'),before.schedules.find(s=>s.id==='s6'));
 assert.deepEqual(state,before);
});

test('single remaining weekday edit retains ID and creates no empty-days schedule',()=>{
 const state=demoState(), item=state.schedules.find(s=>s.id==='s2'); item.days=[3];
 const next=applyScheduleChange(state,changed(item,{start:'14:20'}),'s2','weekday','2026-11-04');
 assert.equal(next.schedules.find(s=>s.title==='영어 학원').id,'s2');
 assert(next.schedules.filter(s=>s.kind!=='school').every(s=>s.days.length>0||s.date));
 assert.deepEqual(next.schedules.find(s=>s.id==='s2').days,[3]);
});

test('weekday edit cannot move schedule to another child',()=>{
 const state=demoState(),item=state.schedules.find(s=>s.id==='s2');
 assert.throws(()=>applyScheduleChange(state,changed(item,{childId:'child-b'}),'s2','weekday','2026-11-04'),/자녀를 바꾸려면/);
});

test('date override leaves following week intact',()=>{
 const state=demoState(),item=state.schedules.find(s=>s.id==='s2');
 const next=applyScheduleChange(state,changed(item,{start:'15:00',end:'16:00'}),'s2','date','2026-11-04');
 validateState(next);
 assert(!onDate(next,'2026-11-04','child-a').some(s=>s.id==='s2'));
 assert(onDate(next,'2026-11-04','child-a').some(s=>s.title==='영어 학원'&&s.start==='15:00'));
 assert(onDate(next,'2026-11-11','child-a').some(s=>s.id==='s2'&&s.start==='14:00'));
});

test('weekday split preserves repeated exclusions',()=>{
 const state=demoState(),item=state.schedules.find(s=>s.id==='s2');item.exclusions=['2026-11-04','2026-11-06'];
 const next=applyScheduleChange(state,changed(item,{start:'14:30'}),'s2','weekday','2026-11-04');
 const parts=next.schedules.filter(s=>s.title==='영어 학원');
 assert.equal(parts.length,2); for(const part of parts)assert.deepEqual(part.exclusions,['2026-11-04','2026-11-06']);
});

test('privacy projection removes identifying details without mutating source',()=>{
 const state=demoState(),before=structuredClone(state),projection=privacyProjection(state),text=JSON.stringify(projection);
 for(const value of ['서윤','도윤','이음초등학교','리틀 영어','이음 태권도','010-0000-0000','영어학원 1호차','태권도 2호차','예시 일정입니다.'])assert(!text.includes(value),`found ${value}`);
 assert.deepEqual(state,before);
});
