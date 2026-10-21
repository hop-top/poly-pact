CREATE ROLE report_maya LOGIN NOSUPERUSER NOBYPASSRLS;

CREATE TABLE public.customer_reports (
    report_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    permitted_principal name NOT NULL,
    body text NOT NULL
);

REVOKE ALL ON public.customer_reports FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO report_maya;
GRANT SELECT ON public.customer_reports TO report_maya;

ALTER TABLE public.customer_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.customer_reports FORCE ROW LEVEL SECURITY;

CREATE POLICY maya_report_read
ON public.customer_reports
FOR SELECT
TO report_maya
USING (
    tenant_id = 'northstar'
    AND permitted_principal = current_user
);
