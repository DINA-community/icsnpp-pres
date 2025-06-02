module pres;

redef record connection += {
    iso_pres_context_identifier: table[int] of string &default=table();
};

