// Bound response allocation while streaming, not after arrayBuffer() has allocated it.
export async function boundedBytes(response,limit){
 const announced=Number(response.headers?.get('content-length'));if(announced>limit)throw Error('Превышен размер ответа');
 if(!response.body)throw Error('Пустой ответ');const reader=response.body.getReader(),parts=[];let size=0;
 try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>limit)throw Error('Превышен размер ответа');parts.push(value)}}finally{await reader.cancel().catch(()=>{})}
 const bytes=new Uint8Array(size);let at=0;for(const part of parts){bytes.set(part,at);at+=part.length}return bytes;
}
