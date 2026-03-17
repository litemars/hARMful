#ifndef EVASION_H
#define EVASION_H

int detect_virtualization(void);
int detect_debugging(void);
int check_process_list(void);
int evasion_checks(void);
int check_file_signatures(void);


#endif // EVASION_H
