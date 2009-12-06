--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = off;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET escape_string_warning = off;

SET search_path = public, pg_catalog;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: smtp_transaction_recipients; Type: TABLE; Schema: public; Owner: mipanel; Tablespace: 
--

CREATE TABLE smtp_transaction_recipients (
    smtp_transaction_recipient_id integer NOT NULL,
    smtp_transaction_id integer NOT NULL,
    recipient text
);


ALTER TABLE public.smtp_transaction_recipients OWNER TO mipanel;

--
-- Name: smtp_transaction_recipients_smtp_transaction_recipient_id_seq; Type: SEQUENCE; Schema: public; Owner: mipanel
--

CREATE SEQUENCE smtp_transaction_recipients_smtp_transaction_recipient_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


ALTER TABLE public.smtp_transaction_recipients_smtp_transaction_recipient_id_seq OWNER TO mipanel;

--
-- Name: smtp_transaction_recipients_smtp_transaction_recipient_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: mipanel
--

ALTER SEQUENCE smtp_transaction_recipients_smtp_transaction_recipient_id_seq OWNED BY smtp_transaction_recipients.smtp_transaction_recipient_id;


--
-- Name: smtp_transactions; Type: TABLE; Schema: public; Owner: mipanel; Tablespace: 
--

CREATE TABLE smtp_transactions (
    smtp_transaction_id integer NOT NULL,
    remote_addr inet,
    remote_port integer,
    envelope_sender text,
    "time" timestamp without time zone,
    subject text,
    smtp_status_code integer,
    smtp_status_message text,
    module character varying(30),
    size integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.smtp_transactions OWNER TO mipanel;

--
-- Name: smtp_transactions_smtp_transaction_id_seq; Type: SEQUENCE; Schema: public; Owner: mipanel
--

CREATE SEQUENCE smtp_transactions_smtp_transaction_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


ALTER TABLE public.smtp_transactions_smtp_transaction_id_seq OWNER TO mipanel;

--
-- Name: smtp_transactions_smtp_transaction_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: mipanel
--

ALTER SEQUENCE smtp_transactions_smtp_transaction_id_seq OWNED BY smtp_transactions.smtp_transaction_id;


--
-- Name: smtp_transaction_recipient_id; Type: DEFAULT; Schema: public; Owner: mipanel
--

ALTER TABLE smtp_transaction_recipients ALTER COLUMN smtp_transaction_recipient_id SET DEFAULT nextval('smtp_transaction_recipients_smtp_transaction_recipient_id_seq'::regclass);


--
-- Name: smtp_transaction_id; Type: DEFAULT; Schema: public; Owner: mipanel
--

ALTER TABLE smtp_transactions ALTER COLUMN smtp_transaction_id SET DEFAULT nextval('smtp_transactions_smtp_transaction_id_seq'::regclass);


--
-- Name: smtp_transaction_recipients_pkey; Type: CONSTRAINT; Schema: public; Owner: mipanel; Tablespace: 
--

ALTER TABLE ONLY smtp_transaction_recipients
    ADD CONSTRAINT smtp_transaction_recipients_pkey PRIMARY KEY (smtp_transaction_recipient_id);


--
-- Name: smtp_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: mipanel; Tablespace: 
--

ALTER TABLE ONLY smtp_transactions
    ADD CONSTRAINT smtp_transactions_pkey PRIMARY KEY (smtp_transaction_id);


--
-- Name: smtp_transaction_recipients_smtp_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: mipanel
--

ALTER TABLE ONLY smtp_transaction_recipients
    ADD CONSTRAINT smtp_transaction_recipients_smtp_transaction_id_fkey FOREIGN KEY (smtp_transaction_id) REFERENCES smtp_transactions(smtp_transaction_id);


--
-- PostgreSQL database dump complete
--

