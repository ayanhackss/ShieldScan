#!/bin/bash
install_path=/www/server/panel/plugin/malwarescan
panel_path=/www/server/panel

Install() {
    echo 'Installing Malware Scanner (Production)...'
    mkdir -p $install_path/{quarantine,logs,rules,status,reports,wp_cache}
    chmod 700 $install_path/quarantine

    # Core dependencies (pinned versions)
    pip3 install 'yara-python==4.3.1' 'requests==2.31.0' 'reportlab==4.1.0' 'pymysql==1.1.0' 'inotify==0.2.10' 2>/dev/null || \
    pip install 'yara-python==4.3.1' 'requests==2.31.0' 'reportlab==4.1.0' 'pymysql==1.1.0' 'inotify==0.2.10' 2>/dev/null || \
    echo 'Some optional deps failed (scanner works without them)'

    # WP-CLI (for auto-updates)
    if [ ! -f /usr/local/bin/wp ]; then
        curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar 2>/dev/null
        if [ -f wp-cli.phar ]; then
            chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp
            echo 'WP-CLI installed'
        fi
    fi

    # Cron for scheduled scans
    CRON_CMD="0 * * * * cd $panel_path && python3 -c \"import sys;sys.path.insert(0,'plugin/malwarescan');from malwarescan_main import malwarescan_main;m=malwarescan_main();m.run_scheduled(type('a',(object,),{})())\" >> $install_path/logs/cron.log 2>&1"
    (crontab -l 2>/dev/null | grep -v "malwarescan") | crontab -
    (crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab -

    # Plugin icon
    cp -f $install_path/ico-malwarescan.png /www/server/panel/BTPanel/static/img/soft_ico/ico-malwarescan.png 2>/dev/null

    # Permissions
    chown -R root:root $install_path
    chmod 600 $install_path/malwarescan_main.py
    chmod 600 $install_path/ml_classifier.py
    chmod 600 $install_path/realtime_watcher.py
    chmod 600 $install_path/report_generator.py
    chmod 600 $install_path/wp_advanced.py

    echo 'Install OK'
}

Uninstall() {
    # Backup quarantine metadata before removal
    if [ -d "$install_path/quarantine" ] && [ "$(ls -A $install_path/quarantine 2>/dev/null)" ]; then
        backup_dir="/www/backup/malwarescan_quarantine_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$backup_dir"
        cp -a $install_path/quarantine/*.meta "$backup_dir/" 2>/dev/null
        # Export quarantine manifest
        echo "# ShieldScan Quarantine Backup - $(date)" > "$backup_dir/manifest.txt"
        echo "# Original quarantine files preserved at: $backup_dir" >> "$backup_dir/manifest.txt"
        cp -a $install_path/quarantine/* "$backup_dir/" 2>/dev/null
        echo "Quarantine backed up to: $backup_dir"
    fi

    # Remove cron
    crontab -l 2>/dev/null | grep -v "malwarescan" | crontab -

    # Stop watcher if running
    if [ -f "$install_path/watcher.pid" ]; then
        kill $(cat "$install_path/watcher.pid") 2>/dev/null
    fi

    rm -rf $install_path
    echo 'Uninstall OK'
}

if [ "${1}" == 'install' ]; then
    Install
elif [ "${1}" == 'uninstall' ]; then
    Uninstall
else
    echo "Usage: $0 {install|uninstall}"; exit 1;
fi
