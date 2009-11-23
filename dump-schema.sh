pg_dump -U mipanel mipanel -s \
	-t smtp_transactions \
	-t smtp_transaction_recipients \
	> schema.sql
