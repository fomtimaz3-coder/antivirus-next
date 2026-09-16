// Native selects remain the source of truth; the dialog supplies consistent mobile styling.
const controls=new Map();
export function syncControls(){for(const [select,button] of controls){button.querySelector('.select-value').textContent=select.selectedOptions[0]?.textContent||'';button.disabled=select.disabled;button.setAttribute('aria-label',button.dataset.label+': '+button.querySelector('.select-value').textContent)}}
export function setupControls(){
 const dialog=document.createElement('dialog');dialog.className='select-dialog';dialog.id='selectDialog';dialog.setAttribute('aria-labelledby','selectTitle');
 dialog.innerHTML='<div class="dialog-head"><h2 id="selectTitle"></h2><button type="button" aria-label="Закрыть выбор">✕</button></div><div class="select-options"></div>';
 document.body.append(dialog);dialog.querySelector('button').onclick=()=>dialog.close();let owner;
 dialog.addEventListener('close',()=>{owner?.setAttribute('aria-expanded','false');owner?.focus()});
 for(const select of document.querySelectorAll('select')){
  const button=document.createElement('button');button.type='button';button.className='select-trigger';button.dataset.label=select.labels?.[0]?.childNodes[0]?.textContent.trim()||select.getAttribute('aria-label')||'Выбор';button.setAttribute('aria-haspopup','dialog');button.setAttribute('aria-controls','selectDialog');button.setAttribute('aria-expanded','false');button.innerHTML='<span class="select-value"></span><span aria-hidden="true">⌄</span>';
  select.after(button);select.hidden=true;controls.set(select,button);select.addEventListener('change',syncControls);
  button.onclick=()=>{owner=button;dialog.querySelector('h2').textContent=button.dataset.label;const list=dialog.querySelector('.select-options');list.replaceChildren();for(const option of select.options){const label=document.createElement('label');label.className='select-option';const radio=document.createElement('input');radio.type='radio';radio.name='setting-choice';radio.checked=option.selected;radio.disabled=option.disabled;radio.value=option.value;const text=document.createElement('span');text.textContent=option.textContent;label.append(radio,text);list.append(label);radio.onchange=()=>{select.value=radio.value;select.dispatchEvent(new Event('change',{bubbles:true}));syncControls();dialog.close()}}button.setAttribute('aria-expanded','true');dialog.showModal();list.querySelector('input:checked')?.focus()};
 }
 syncControls();
}
