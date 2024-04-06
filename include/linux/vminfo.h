/* 5-level table support + data found at the location (buffer) */ 
struct vminfo_struct {
    unsigned long pgd;
    unsigned long p4d;
    unsigned long pud;
    unsigned long pmd;
    unsigned long pte;

    unsigned long value;
};

