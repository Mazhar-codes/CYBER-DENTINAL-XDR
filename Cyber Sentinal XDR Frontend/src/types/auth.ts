export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  device_token?: string | null;  // returned when trust_device=true after 2FA
}

export interface UserResponse {
  id: string;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
  two_factor_enabled: boolean;
  created_at: string;
  last_login: string | null;
}

export interface MFASetupResponse {
  secret: string;
  qr_code_url: string;
  qr_code_base64: string;
  backup_codes: string[];   // shown once — user must save these
}

export interface BackupCodesResponse {
  backup_codes: string[];
  count: number;
  message: string;
}

export interface TrustedDevice {
  id: string;
  ip_address: string;
  user_agent: string;
  trusted_until: string;
  created_at: string;
}

export interface LoginResponse {
  requires_2fa: true;
  temp_token: string;
  // Set when user must complete first-time TOTP setup before tokens are issued
  requires_setup?: boolean;
  secret?: string;
  qr_code_url?: string;
  qr_code_base64?: string;
  backup_codes?: string[];
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  ip: string;
  status: 'success' | 'failure';
  detail?: string;
}

export interface AuthError {
  code: string;
  message: string;
  field?: string;
}
