-- =====================================================
-- staff — ажилтны хүснэгт
-- Supabase → SQL Editor-т бүтнээр нь хуулж Run дарна.
-- =====================================================

create table if not exists public.staff (
  id         bigint generated always as identity primary key,
  full_name  text not null,
  position   text not null,
  phone      text,
  email      text,
  status     text not null default 'active'
             check (status in ('active', 'leave', 'inactive')),
  hired_on   date,
  created_at timestamptz not null default now()
);

-- RLS (Row Level Security) асаах
alter table public.staff enable row level security;

-- Жишээ өгөгдөл (3 мөр)
insert into public.staff (full_name, position, phone, email, status, hired_on) values
  ('Б. Ганбаатар', 'Ахлах инженер',                 '8800-1101', 'ganbaatar@example.com', 'active', '2020-03-02'),
  ('Д. Энхтуяа',   'Бетон цутгалтын мастер',        '8800-1102', 'enkhtuya@example.com',  'active', '2021-05-17'),
  ('Э. Тэмүүжин',  'Тоног төхөөрөмжийн оператор',   '8800-1103', null,                    'leave',  '2023-09-04');
