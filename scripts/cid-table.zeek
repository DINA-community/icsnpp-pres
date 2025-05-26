module pres;

redef record connection += {
    iso_8650_context_identifier: table[int] of string &default=table();
};

