// Test the actual JSX component, not a duplicate implementation.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const babel = require('@babel/core');
const React = require('react');
const Renderer = require('react-test-renderer');
const {act} = Renderer;
const html = fs.readFileSync(path.join(__dirname,'../web/index.html'),'utf8');
const component = html.slice(html.indexOf('    function QPatchPanel('),html.indexOf('    function IncidentBrief()'));
const compiled = babel.transformSync(component,{presets:[require.resolve('@babel/preset-react')]}).code;
const QPatchPanel = new Function('React','useState',compiled+';return QPatchPanel;')(React,React.useState);
const scan = {metadata:{scan_id:'saved-older'}};
const finding = {finding_id:'actual-md5'};
const proposal = {status:'proposal',explanation:'MD5 collision risk',remediation:'SHA-256 for declared integrity',architectural_changes:[],validation_steps:['Verify digest consumers'],warnings:['Review required'],diff:'--- a/digest.py\n+++ b/digest.py\n',source_sha256:'hash'};
function button(root,text){return root.findAllByType('button').find(x=>x.children.join('').includes(text));}
test('all existing dashboard JSX compiles',()=>{
  const full = html.match(/<script[^>]*type="text\/babel"[^>]*>([\s\S]*?)<\/script>/)[1];
  assert.ok(babel.transformSync(full,{presets:[require.resolve('@babel/preset-react')]}).code);
});
test('consent, purpose and selected finding generate a rendered proposal',async()=>{
  const calls=[];
  const original=global.fetch;
  global.fetch=async(url,options)=>{calls.push([url,JSON.parse(options.body)]);return {ok:true,json:async()=>proposal};};
  let view;
  try {
    await act(async()=>{view=Renderer.create(React.createElement(QPatchPanel,{scan,finding}));});
    assert.equal(button(view.root,'Generate').props.disabled,true);
    await act(async()=>{view.root.findByType('select').props.onChange({target:{value:'integrity'}});view.root.findByType('input').props.onChange({target:{checked:true}});});
    await act(async()=>{await button(view.root,'Generate').props.onClick();});
    assert.deepEqual(calls,[['/api/q-patch',{scan_id:'saved-older',finding_id:'actual-md5',purpose:'integrity',consent:true}]]);
    assert.equal(view.root.findByType('pre').children[0],proposal.diff);
    assert.ok(button(view.root,'Download proposed diff'));
    assert.equal(button(view.root,'Generate').props.disabled,false);
  } finally {if(view) view.unmount();global.fetch=original;}
});
test('provider errors are displayed and no patch is rendered',async()=>{
  const original=global.fetch;
  global.fetch=async()=>({ok:false,json:async()=>({error:'Configure backend AI'})});
  let view;
  try {
    await act(async()=>{view=Renderer.create(React.createElement(QPatchPanel,{scan,finding}));});
    await act(async()=>{view.root.findByType('input').props.onChange({target:{checked:true}});});
    await act(async()=>{await button(view.root,'Generate').props.onClick();});
    assert.equal(view.root.findByProps({role:'alert'}).children[0],'Configure backend AI');
    assert.equal(view.root.findAllByType('pre').length,0);
  } finally {if(view)view.unmount();global.fetch=original;}
});
test('unsaved and demo scans cannot submit',async()=>{
  for (const metadata of [{},{scan_id:'demo',is_demo:true}]) {
    let view;
    await act(async()=>{view=Renderer.create(React.createElement(QPatchPanel,{scan:{metadata},finding}));});
    assert.equal(view.root.findAllByType('button').length,0);
    view.unmount();
  }
});
