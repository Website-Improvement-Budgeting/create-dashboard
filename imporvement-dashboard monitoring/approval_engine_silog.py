# SILOG Shared Approval Engine — satu sumber aturan transaksi Approval.
# Dipanggil oleh endpoint Approval Satuan dan Konfirmasi Excel.
# Cursor harus berada di dalam `with conn:` agar satu request bersifat atomik.
from datetime import date
from decimal import Decimal

class ApprovalEngineError(ValueError):
    pass

def D(v):
    x = Decimal(str(v))
    if not x.is_finite():
        raise ApprovalEngineError("Nilai budget tidak valid.")
    return x

def budget_plan(request_amount, available, current, consumable):
    amount, av, cur, con = map(D, (request_amount, available, current, consumable))
    if amount <= 0 or min(av, cur, con) < 0 or con > cur:
        raise ApprovalEngineError("Data nominal atau saldo budget tidak valid.")
    shortage = max(Decimal(0), amount - av)
    hold = cur - con
    hold_to_open = min(shortage, hold)
    return {"request_amount": amount, "available": av, "shortage": shortage,
            "hold": hold, "hold_to_open": hold_to_open,
            "required_reallocation": shortage - hold_to_open,
            "mode": ("approve" if shortage == 0 else
                     "open" if hold >= shortage else "reallocate")}

def _history(cur, uid, rid, bid, action, field, old, new, amount):
    cur.execute("""INSERT INTO public.budget_history
        (budget_id,request_id,action,field_name,previous_value,updated_value,amount,created_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
        (bid,rid,action,field,old,new,amount,uid))

def _allocation(cur, uid, rid, sid, tid, typ, amount, note):
    cur.execute("""INSERT INTO public.budget_allocation
        (request_id,source_budget_id,target_budget_id,allocation_type,amount,instruction,approved_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s)""", (rid,sid,tid,typ,amount,note,uid))

def _set_fields(cur, uid, rid, bid, old, new, action, amount):
    fields = [f for f in ("current_budget","consumable_budget","consumed_budget","available_amount") if old[f] != new[f]]
    if not fields:
        return
    assignments = ', '.join(f'{field} = %s' for field in fields)
    cur.execute(f"UPDATE public.budget_master SET {assignments} WHERE budget_id = %s",
                tuple(new[f] for f in fields)+(bid,))
    for f in fields:
        _history(cur,uid,rid,bid,action,f,old[f],new[f],amount)

def _snapshot(row):
    return {k:D(row[k]) for k in ("current_budget","consumable_budget","consumed_budget","available_amount")}

def _consume(cur,uid,rid,bid,balance,amount):
    if balance['available_amount'] < amount:
        raise ApprovalEngineError("Available Budget tidak mencukupi untuk konsumsi transaksi.")
    nxt=dict(balance)
    nxt['consumed_budget']+=amount
    nxt['available_amount']-=amount
    _set_fields(cur,uid,rid,bid,balance,nxt,'Consume Budget',amount)
    return nxt

def execute_approval(cur, user_id, request_id, mode='auto', allocations=None,
                     instruction='', expected_batch_id=None, open_amount=None):
    """Execute exactly one request atomically inside caller transaction.

    mode: auto (Excel '+'), approve (manual direct), open (manual open),
          reallocate (manual / Excel minus-plus).
    Caller must own transaction and must commit only on success.
    """
    if mode not in {'auto','approve','open','reallocate'}:
        raise ApprovalEngineError('Jenis Approval tidak dikenali.')
    cur.execute("""SELECT br.request_id,br.request_status,br.request_amount,br.budget_id,br.batch_id,
                          f.fund_code AS target_fund_code,
                          tfc.funds_center_code AS target_funds_center_code,
                          tci.commitment_item_code AS target_commitment_item_code
                   FROM public.budget_request br
                   LEFT JOIN public.fund f ON f.fund_id=br.mapped_fund_id
                   LEFT JOIN public.funds_center tfc ON tfc.funds_center_id=br.mapped_funds_center_id
                   LEFT JOIN public.commitment_item tci ON tci.commitment_item_id=br.mapped_commitment_item_id
                   WHERE br.request_id=%s FOR UPDATE OF br""", (request_id,))
    req=cur.fetchone()
    if not req:
        raise ApprovalEngineError('Pengajuan tidak ditemukan.')
    if req['request_status']!='Pending':
        raise ApprovalEngineError('Hanya pengajuan Pending yang dapat diproses.')
    if req['budget_id'] is None:
        raise ApprovalEngineError('Sumber budget tujuan tidak ditemukan.')
    if expected_batch_id is not None and req['batch_id'] != expected_batch_id:
        raise ApprovalEngineError('Request ID bukan anggota batch yang dipilih.')
    lines=allocations or []
    if mode=='reallocate' and not lines:
        raise ApprovalEngineError('Sumber realokasi wajib diisi.')
    ids=[req['budget_id']]+[a['source_budget_id'] for a in lines]
    if any(not isinstance(b,int) or isinstance(b,bool) or b<=0 for b in ids):
        raise ApprovalEngineError('ID budget tidak valid.')
    if req['budget_id'] in ids[1:]:
        raise ApprovalEngineError('Budget donor dan target tidak boleh sama.')
    # Lock deterministically across all affected budget records.
    cur.execute("""SELECT bm.budget_id,bm.entity_id,bm.biro_id,bm.budget_year,
                 UPPER(TRIM(bm.budget_scope)) AS budget_scope,bm.funds_center_id,
                 bm.commitment_item_id,bm.current_budget,bm.consumable_budget,
                 bm.consumed_budget,bm.available_amount,
                 fc.funds_center_code,ci.commitment_item_code,
                 hist.fund_code
                 FROM public.budget_master bm
                 LEFT JOIN public.funds_center fc ON fc.funds_center_id=bm.funds_center_id
                 LEFT JOIN public.commitment_item ci ON ci.commitment_item_id=bm.commitment_item_id
                 LEFT JOIN LATERAL (
                    SELECT f.fund_code FROM public.budget_request old_req
                    JOIN public.fund f ON f.fund_id=old_req.mapped_fund_id
                    WHERE old_req.budget_id=bm.budget_id
                    ORDER BY old_req.request_date DESC,old_req.request_id DESC LIMIT 1
                 ) hist ON TRUE
                 WHERE bm.budget_id=ANY(%s) ORDER BY bm.budget_id FOR UPDATE OF bm""", (sorted(set(ids)),))
    locked={r['budget_id']:r for r in cur.fetchall()}
    if len(locked)!=len(set(ids)):
        raise ApprovalEngineError('Salah satu budget donor atau target tidak ditemukan.')
    target=locked[req['budget_id']]
    amount=D(req['request_amount'])
    plan=budget_plan(amount,target['available_amount'],target['current_budget'],target['consumable_budget'])
    resolved_mode=plan['mode'] if mode=='auto' else mode
    if resolved_mode=='approve' and plan['shortage']>0:
        raise ApprovalEngineError('Available Budget belum mencukupi. Gunakan Open Budget atau Reallocation.')
    if resolved_mode=='open':
        if plan['mode']!='open':
            raise ApprovalEngineError('Open Budget tidak diperlukan atau Approval Hold tidak mencukupi.')
        if open_amount is not None and D(open_amount)!=plan['shortage']:
            raise ApprovalEngineError(f"Nominal Open Budget harus tepat {plan['shortage']:.2f}.")
    if resolved_mode=='reallocate' and plan['required_reallocation']<=0:
        raise ApprovalEngineError('Realokasi tidak diperlukan. Gunakan Approve atau Open Budget.')
    if resolved_mode!='reallocate' and lines:
        raise ApprovalEngineError('Sumber donor tidak diperlukan untuk jenis transaksi ini.')
    balances={bid:_snapshot(record) for bid,record in locked.items()}
    state=balances[req['budget_id']]
    opened=Decimal(0)
    reallocated=Decimal(0)
    if resolved_mode in ('open','reallocate'):
        opened=plan['shortage'] if resolved_mode=='open' else plan['hold_to_open']
        if opened>0:
            nxt=dict(state)
            nxt['consumable_budget']+=opened
            nxt['available_amount']+=opened
            _set_fields(cur,user_id,request_id,req['budget_id'],state,nxt,'Open Budget',opened)
            _allocation(cur,user_id,request_id,None,req['budget_id'],'Open Budget',opened,
                        instruction if resolved_mode=='open' else ('Membuka Approval Hold sebelum realokasi. '+instruction).strip())
            state=nxt
    if resolved_mode=='reallocate':
        scope=target['budget_scope']
        if scope not in ('FC_CI','CI_ONLY'):
            raise ApprovalEngineError('Budget Scope target tidak dikenali.')
        totals={}
        for idx,a in enumerate(lines,1):
            source=locked[a['source_budget_id']]
            quantity=D(a['amount'])
            if quantity<=0 or quantity.quantize(Decimal('0.01'))!=quantity:
                raise ApprovalEngineError(f'Nominal donor baris {idx} tidak valid.')
            if (source['entity_id'],source['biro_id'])==(target['entity_id'],target['biro_id']):
                raise ApprovalEngineError(f'Donor baris {idx} harus berasal dari biro atau entity lain.')
            if source['budget_year']!=target['budget_year'] or source['budget_scope']!=scope:
                raise ApprovalEngineError(f'Tahun atau Budget Scope donor baris {idx} tidak sesuai.')
            if source['commitment_item_id']!=target['commitment_item_id']:
                raise ApprovalEngineError(f'Commitment Item donor baris {idx} tidak sesuai.')
            if scope=='FC_CI' and source['funds_center_id']!=target['funds_center_id']:
                raise ApprovalEngineError(f'Funds Center donor baris {idx} tidak sesuai.')
            for field in ('entity_id','biro_id'):
                if a.get(field) not in (None,'') and str(a[field])!=str(source[field]):
                    raise ApprovalEngineError(f'{field} donor baris {idx} tidak sesuai.')
            # Fund berasal dari mapping Profit Center pada PENGAJUAN,
            # bukan kunci identitas budget_master donor. Riwayat pengajuan
            # donor bisa tidak tersedia atau berubah; jangan jadikan Fund
            # historis syarat perpindahan anggaran. Kunci donor divalidasi
            # dengan scope + tahun + CI (+FC untuk FC_CI) dan entity/biro.
            if str(a.get('commitment_item_code') or '').strip().upper()!=str(source['commitment_item_code'] or '').strip().upper():
                raise ApprovalEngineError(f'Commitment Item donor baris {idx} tidak sesuai dengan master.')
            if scope=='FC_CI' and str(a.get('funds_center_code') or '').strip().upper()!=str(source['funds_center_code'] or '').strip().upper():
                raise ApprovalEngineError(f'Funds Center donor baris {idx} tidak sesuai dengan master.')
            # CI_ONLY: do not check Funds Center at all.
            totals[a['source_budget_id']]=totals.get(a['source_budget_id'],Decimal(0))+quantity
            reallocated+=quantity
        if reallocated != plan['required_reallocation']:
            raise ApprovalEngineError(f"Total realokasi harus tepat {plan['required_reallocation']:.2f}.")
        for sid,qty in totals.items():
            old=balances[sid]
            if old['available_amount']<qty:
                raise ApprovalEngineError(f'Available Budget donor {sid} tidak mencukupi.')
            nxt=dict(old)
            for field in ('current_budget','consumable_budget','available_amount'):
                nxt[field]-=qty
            if min(nxt.values())<0:
                raise ApprovalEngineError(f'Realokasi membuat saldo donor {sid} negatif.')
            _set_fields(cur,user_id,request_id,sid,old,nxt,'Reallocation Out',qty)
        nxt=dict(state)
        for field in ('current_budget','consumable_budget','available_amount'):
            nxt[field]+=reallocated
        _set_fields(cur,user_id,request_id,req['budget_id'],state,nxt,'Reallocation In',reallocated)
        state=nxt
        allocation_type='Reallocation FC_CI' if scope=='FC_CI' else 'Reallocation CI_Only'
        for a in lines:
            textdate=a.get('allocation_date')
            if hasattr(textdate,'isoformat'): textdate=textdate.isoformat()
            note=f'Tanggal realokasi: {textdate or date.today().isoformat()}'
            # Snapshot mapping disimpan pada catatan histori realokasi; Fund donor
            # hanya dicatat jika memang tersedia dari riwayat mapping donor.
            source_row=locked[a['source_budget_id']]
            source_fund=source_row.get('fund_code')
            note += (
                f" | Source mapping: Fund={source_fund or 'NULL'}"
                f"; Funds Center={source_row.get('funds_center_code') or 'NULL'}"
                f"; Commitment Item={source_row.get('commitment_item_code') or 'NULL'}"
                f" | Target mapping: Fund={req.get('target_fund_code') or 'NULL'}"
                f"; Funds Center={req.get('target_funds_center_code') or 'NULL'}"
                f"; Commitment Item={req.get('target_commitment_item_code') or 'NULL'}"
            )
            if a.get('instruction'): note+=' | '+str(a['instruction'])
            _allocation(cur,user_id,request_id,a['source_budget_id'],req['budget_id'],allocation_type,D(a['amount']),note)
    _consume(cur,user_id,request_id,req['budget_id'],state,amount)
    decision={'approve':'Approve','open':'Open Budget','reallocate':'Approve with Reallocation'}[resolved_mode]
    cur.execute("""UPDATE public.budget_request SET request_status='Approved',budget_status='Budget Cukup'
                   WHERE request_id=%s""",(request_id,))
    cur.execute("""INSERT INTO public.approval_decision
                  (request_id,approval_user_id,decision,instruction,approved_amount)
                  VALUES (%s,%s,%s,%s,%s)""",(request_id,user_id,decision,instruction,
                   amount))
    messages={'approve':'Pengajuan berhasil disetujui tanpa Open Budget.',
              'open':'Open Budget berhasil diproses.',
              'reallocate':'Approve with Reallocation berhasil diproses. Approval Hold dibuka terlebih dahulu, kekurangan dipenuhi melalui realokasi, lalu seluruh Request Amount dikonsumsi.'}
    return {'request_id':request_id,'message':messages[resolved_mode],
            'request_status':'Approved','budget_status':'Budget Cukup',
            'approval_decision':decision,'approved_amount':str(amount),
            'opened_amount':str(opened),'opened_from_hold':str(opened),
            'allocated_amount':str(reallocated),'remaining_shortage':'0'}
