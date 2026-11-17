-- =====================================================
-- Supabase: content_drafts, bookings, users хүснэгтүүд
-- =====================================================

-- -----------------------------------------------------
-- 1. content_drafts — ноорог пост
-- -----------------------------------------------------
create table if not exists public.content_drafts (
  id           bigint generated always as identity primary key,
  title        text not null,
  content      text,
  platform     text check (platform in ('facebook', 'instagram', 'tiktok', 'website')),
  status       text not null default 'draft'
               check (status in ('draft', 'review', 'scheduled', 'published')),
  scheduled_at timestamptz,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

-- -----------------------------------------------------
-- 2. bookings — захиалга
-- -----------------------------------------------------
create table if not exists public.bookings (
  id             bigint generated always as identity primary key,
  customer_name  text not null,
  customer_phone text not null,
  customer_email text,
  service        text not null,
  booking_date   date not null,
  booking_time   time not null,
  guests         integer not null default 1 check (guests > 0),
  status         text not null default 'pending'
                 check (status in ('pending', 'confirmed', 'cancelled', 'completed')),
  note           text,
  created_at     timestamptz not null default now()
);

-- -----------------------------------------------------
-- 3. users — нэвтрэх хэрэглэгч
-- -----------------------------------------------------
create table if not exists public.users (
  id            uuid primary key default gen_random_uuid(),
  email         text not null unique,
  password_hash text not null,
  role          text not null default 'admin'
                check (role in ('admin', 'editor', 'viewer')),
  is_active     boolean not null default true,
  created_at    timestamptz not null default now()
);

-- -----------------------------------------------------
-- RLS (Row Level Security) асаах
-- -----------------------------------------------------
alter table public.content_drafts enable row level security;
alter table public.bookings       enable row level security;
alter table public.users          enable row level security;

-- -----------------------------------------------------
-- Жишээ өгөгдөл: content_drafts (3 мөр)
-- -----------------------------------------------------
insert into public.content_drafts (title, content, platform, status, scheduled_at) values
  ('Шинэ цэсний танилцуулга',
   'Энэ долоо хоногоос манай шинэ өвлийн цэс эхэллээ. Халуун шөл, шинэ амттан таныг хүлээж байна!',
   'facebook', 'draft', null),
  ('Амралтын өдрийн хямдрал',
   'Бямба, Ням гарагт бүх үйлчилгээ 20% хямдралтай. Урьдчилан захиалаарай!',
   'instagram', 'review', null),
  ('Шинэ жилийн баярын захиалга',
   'Шинэ жилийн баярын арга хэмжээний захиалга авч эхэллээ. Суудал хязгаартай.',
   'facebook', 'scheduled', '2026-12-01 10:00:00+08');

-- -----------------------------------------------------
-- Жишээ өгөгдөл: bookings (3 мөр)
-- -----------------------------------------------------
insert into public.bookings (customer_name, customer_phone, customer_email, service, booking_date, booking_time, guests, status, note) values
  ('Бат-Эрдэнэ', '99112233', 'bat@example.com',    'Ширээ захиалга', '2026-11-20', '19:00', 4, 'confirmed', 'Цонхны дэргэдэх ширээ'),
  ('Сарангэрэл', '88223344', 'saraa@example.com',  'Төрсөн өдөр',    '2026-11-25', '18:30', 10, 'pending', 'Бялуу авчирна'),
  ('Тэмүүлэн',   '95334455', null,                 'Ширээ захиалга', '2026-11-15', '13:00', 2, 'cancelled', null);

-- -----------------------------------------------------
-- Анхны хэрэглэгч (нууц үгийг bcrypt-ээр урьдчилан шифрлэсэн,
-- жинхэнэ нууц үг энэ файлд хадгалагдаагүй)
-- -----------------------------------------------------
insert into public.users (email, password_hash, role) values
  ('bbatchimeg017@gmail.com',
   '$2a$12$xIOpe3hNtVLbELKq4e/CGux6FdfiDiEaD7DBjepHoP/egeBRHhIde',
   'admin')
on conflict (email) do nothing;
