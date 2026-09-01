# En cas de coupure réseau pendant un essai

Le kill switch bloque tout ce qui ne passe pas par le tunnel. Si le service
meurt en le laissant armé, la machine se retrouve sans réseau. Ces quatre
commandes rendent la main immédiatement.

```bash
sudo pfctl -a com.deliriuum.direct -F all
sudo pfctl -d
sudo route -n delete -net 0.0.0.0/1
sudo route -n delete -net 128.0.0.0/1
sudo networksetup -setdnsservers Wi-Fi Empty
sudo networksetup -setv6automatic Wi-Fi
```

Puis restaurer la configuration pf d'origine :

```bash
sudo cp /var/lib/deliriuum-direct/pf.conf.backup /etc/pf.conf
sudo pfctl -f /etc/pf.conf
```

Le service fait ce nettoyage tout seul à son démarrage, donc un simple
redémarrage de la machine suffit aussi.
