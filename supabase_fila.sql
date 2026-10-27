-- =====================================================================
--  Sistema de Chamada de Pacientes — UBS
--  Cole tudo no Supabase: SQL Editor > New query > Run
--  ANTES de rodar, troque 'TROQUE-ESTA-SENHA' (linha da senha) por uma
--  senha forte. É ela que a recepção, os profissionais e a TV vão digitar.
--  Pode rodar de novo sem problema (também atualiza a versão anterior).
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- SENHA DA UNIDADE (guardada como hash) ----------
create table if not exists public.ubs_config (
  id int primary key default 1 check (id = 1),
  senha_hash text not null
);
alter table public.ubs_config enable row level security;   -- sem políticas: ninguém lê pela API

insert into public.ubs_config (id, senha_hash)
values (1, extensions.crypt('TROQUE-ESTA-SENHA', extensions.gen_salt('bf')))
on conflict (id) do update set senha_hash = excluded.senha_hash;

-- ---------- FILA ----------
create table if not exists public.ubs_fila (
  id          bigint generated always as identity primary key,
  nome        text not null check (char_length(nome) between 2 and 120),
  destino     text not null,                       -- id do setor (triagem, medico, prenatal...)
  nivel       text not null default 'normal',      -- urgencia | prioritario | normal
  status      text not null default 'aguardando',
  criado_em   timestamptz not null default now(),  -- chegada na recepção
  ordem       timestamptz not null default now(),  -- posição na fila do setor atual
  chamado_em  timestamptz,
  chamado_por text
);
-- atualização de quem rodou a versão anterior (que tinha a coluna "prioridade")
alter table public.ubs_fila add column if not exists nivel text not null default 'normal';
do $$ begin
  if exists (select 1 from information_schema.columns
             where table_schema='public' and table_name='ubs_fila' and column_name='prioridade') then
    update public.ubs_fila set nivel = 'prioritario' where prioridade;
    alter table public.ubs_fila drop column prioridade;
  end if;
end $$;
alter table public.ubs_fila drop constraint if exists ubs_fila_nivel_check;
alter table public.ubs_fila add  constraint ubs_fila_nivel_check  check (nivel in ('urgencia','prioritario','normal'));
alter table public.ubs_fila drop constraint if exists ubs_fila_status_check;
alter table public.ubs_fila add  constraint ubs_fila_status_check check (status in ('aguardando','chamado','atendido','removido'));

alter table public.ubs_fila enable row level security;      -- sem políticas: acesso só pelas funções abaixo
create index if not exists ubs_fila_criado_idx on public.ubs_fila (criado_em);

-- ---------- FUNÇÕES (todas exigem a senha) ----------
drop function if exists public.fila_adicionar(text, text, text, boolean);
drop function if exists public.fila_mover(text, bigint, text, text);

create or replace function public.ubs_checar(p_senha text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if p_senha is null or not exists (
    select 1 from ubs_config where senha_hash = crypt(p_senha, senha_hash)
  ) then
    raise exception 'senha_invalida';
  end if;
end $$;

-- Lista a fila do dia: urgência > prioritário > normal, depois ordem de chegada.
-- Apaga automaticamente registros com mais de 16 horas (LGPD).
create or replace function public.fila_listar(p_senha text)
returns setof public.ubs_fila
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform ubs_checar(p_senha);
  delete from ubs_fila where criado_em < now() - interval '16 hours';
  return query
    select * from ubs_fila where status <> 'removido'
    order by case nivel when 'urgencia' then 0 when 'prioritario' then 1 else 2 end, ordem;
end $$;

create or replace function public.fila_adicionar(p_senha text, p_nome text, p_destino text, p_nivel text default 'normal')
returns public.ubs_fila
language plpgsql security definer set search_path = public, extensions as $$
declare r ubs_fila;
begin
  perform ubs_checar(p_senha);
  insert into ubs_fila (nome, destino, nivel)
  values (trim(p_nome), p_destino, coalesce(p_nivel, 'normal'))
  returning * into r;
  return r;
end $$;

-- Chama um paciente. Retorna null se outra pessoa já o chamou.
-- O paciente que estava "em atendimento" neste setor passa para "atendido".
create or replace function public.fila_chamar(p_senha text, p_id bigint, p_setor text)
returns public.ubs_fila
language plpgsql security definer set search_path = public, extensions as $$
declare r ubs_fila;
begin
  perform ubs_checar(p_senha);
  update ubs_fila
     set status = 'chamado', chamado_em = now(), chamado_por = p_setor
   where id = p_id
     and (status = 'aguardando' or (status = 'chamado' and chamado_por = p_setor))
  returning * into r;
  if r.id is null then
    return null;
  end if;
  update ubs_fila set status = 'atendido'
   where status = 'chamado' and chamado_por = p_setor and id <> p_id;
  return r;
end $$;

-- Muda status/destino/nível: concluir, remover, encaminhar, corrigir destino ou classificação.
create or replace function public.fila_mover(p_senha text, p_id bigint, p_status text,
                                             p_destino text default null, p_nivel text default null)
returns public.ubs_fila
language plpgsql security definer set search_path = public, extensions as $$
declare r ubs_fila;
begin
  perform ubs_checar(p_senha);
  update ubs_fila
     set status      = p_status,
         destino     = coalesce(p_destino, destino),
         nivel       = coalesce(p_nivel, nivel),
         ordem       = case when p_destino is not null and p_destino <> destino then now() else ordem end,
         chamado_por = case when p_status = 'aguardando' then null else chamado_por end
   where id = p_id
  returning * into r;
  return r;
end $$;

-- ---------- PERMISSÕES ----------
revoke all on function public.ubs_checar(text) from public, anon, authenticated;
grant execute on function public.fila_listar(text)                            to anon, authenticated;
grant execute on function public.fila_adicionar(text, text, text, text)       to anon, authenticated;
grant execute on function public.fila_chamar(text, bigint, text)              to anon, authenticated;
grant execute on function public.fila_mover(text, bigint, text, text, text)   to anon, authenticated;
