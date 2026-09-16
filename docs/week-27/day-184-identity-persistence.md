# Day 184: Identity Database (Users, Roles & Permissions)

## 1. Relational Schema Architecture
Day 184 normalizes user identity and role-based permissions into durable PostgreSQL tables:

┌──────────────┐         ┌─────────────────────┐         ┌────────────────────┐
│    users     │         │        roles        │         │    permissions     │
├──────────────┤         ├─────────────────────┤         ├────────────────────┤
│ id (PK)      │──(N:1)──│ id (PK)             │         │ id (PK)            │
│ username     │         │ name                │         │ name               │
│ email        │         │ description         │         │ description        │
│ password_hash│         └──────────┬──────────┘         └─────────┬──────────┘
│ role_id (FK) │                    │                              │
│ status       │                    └──────────────┬───────────────┘
│ last_activity│                                   │
└──────────────┘                           (Many-to-Many)
│
┌──────────▼──────────┐
│  role_permissions   │
├─────────────────────┤
│ role_id (PK, FK)    │
│ permission_id(PK,FK)│
│ assigned_at         │
└─────────────────────┘


## 2. Security Standards
- **Password Protection**: Passwords hashed using `bcrypt` with unique cryptographic salts. Plaintext passwords are never persisted.
- **Account Lifecycles**: Enum-enforced statuses (`ACTIVE`, `INACTIVE`, `LOCKED`, `SUSPENDED`).
- **Granular Permissions**: 15 distinct operational capabilities mapped to the 5 canonical roles (`ADMIN`, `SECURITY_LEAD`, `SOC_ANALYST`, `AUDITOR`, `VIEWER`).

## 3. Relationship to Week 31
Week 27 establishes the persistent storage layer and repository interfaces. Token generation (JWT/OAuth2), authorization middleware, and session enforcement will build upon this schema during Week 31.