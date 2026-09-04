#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <NetworkExtension/NetworkExtension.h>
#import <SystemExtensions/SystemExtensions.h>

static NSString * const DeliriuumProviderBundleIdentifier =
    @"com.deliriuum.direct.PacketTunnel";

static NETunnelProviderManager *DeliriuumManager = nil;


/* ============================================================
   System Extension activation
   ============================================================ */

@interface DeliriuumSystemExtensionDelegate :
    NSObject <OSSystemExtensionRequestDelegate>

@property(nonatomic) dispatch_semaphore_t semaphore;
@property(nonatomic) BOOL success;
@property(nonatomic) BOOL rebootRequired;
@property(nonatomic, strong) NSString *failure;

@end


@implementation DeliriuumSystemExtensionDelegate

- (void)request:
        (OSSystemExtensionRequest *)request
        didFinishWithResult:(OSSystemExtensionRequestResult)result
{
    if (result == OSSystemExtensionRequestCompleted) {
        self.success = YES;
    }
    else if (result == OSSystemExtensionRequestWillCompleteAfterReboot) {
        self.rebootRequired = YES;
        self.failure =
            @"L’extension VPN a été installée mais nécessite un redémarrage du Mac.";
    }
    else {
        self.failure =
            [NSString stringWithFormat:
                @"Résultat inattendu de l’activation de l’extension système : %ld",
                (long)result];
    }

    dispatch_semaphore_signal(self.semaphore);
}


- (void)request:
        (OSSystemExtensionRequest *)request
        didFailWithError:(NSError *)error
{
    self.failure =
        error.localizedDescription
        ?: @"Impossible d’activer l’extension système Deliriuum.";

    dispatch_semaphore_signal(self.semaphore);
}


- (void)requestNeedsUserApproval:
        (OSSystemExtensionRequest *)request
{
    /*
     macOS affiche sa demande d’autorisation.
     On attend ensuite didFinishWithResult: ou didFailWithError:.
    */
}


- (OSSystemExtensionReplacementAction)request:
        (OSSystemExtensionRequest *)request
        actionForReplacingExtension:
            (OSSystemExtensionProperties *)existing
        withExtension:
            (OSSystemExtensionProperties *)ext
{
    return OSSystemExtensionReplacementActionReplace;
}

@end


static BOOL activate_system_extension(NSString **failure)
{
    DeliriuumSystemExtensionDelegate *delegate =
        [[DeliriuumSystemExtensionDelegate alloc] init];

    delegate.semaphore = dispatch_semaphore_create(0);
    delegate.success = NO;
    delegate.rebootRequired = NO;
    delegate.failure = nil;

    dispatch_queue_t callbackQueue =
        dispatch_queue_create(
            "com.deliriuum.direct.systemextension",
            DISPATCH_QUEUE_SERIAL
        );

    OSSystemExtensionRequest *request =
        [OSSystemExtensionRequest
            activationRequestForExtension:
                DeliriuumProviderBundleIdentifier
            queue:callbackQueue];

    request.delegate = delegate;

    [[OSSystemExtensionManager sharedManager]
        submitRequest:request];

    /*
     L’API Rust appelle ce bridge depuis un thread de commande Tauri.
     On laisse jusqu’à 2 minutes pour une éventuelle approbation macOS.
    */
    dispatch_time_t timeout =
        dispatch_time(
            DISPATCH_TIME_NOW,
            (int64_t)(120 * NSEC_PER_SEC)
        );

    long waitResult =
        dispatch_semaphore_wait(
            delegate.semaphore,
            timeout
        );

    if (waitResult != 0) {
        if (failure != NULL) {
            *failure =
                @"Délai dépassé pendant l’activation de l’extension VPN. "
                 "Vérifiez Réglages Système > Confidentialité et sécurité.";
        }

        return NO;
    }

    if (!delegate.success) {
        if (failure != NULL) {
            *failure =
                delegate.failure
                ?: @"L’extension système Deliriuum n’a pas été activée.";
        }

        return NO;
    }

    return YES;
}


/* ============================================================
   Helpers
   ============================================================ */

static void set_error(
    char *buffer,
    size_t buffer_len,
    NSString *message
)
{
    if (buffer == NULL || buffer_len == 0) {
        return;
    }

    const char *text = [message UTF8String];

    if (text == NULL) {
        buffer[0] = '\0';
        return;
    }

    snprintf(buffer, buffer_len, "%s", text);
}



/* ============================================================
   DATA PROTECTION KEYCHAIN
   ============================================================ */

static NSMutableDictionary *deliriuum_keychain_query(
    NSString *service,
    NSString *account
)
{
    return [@{
        (__bridge id)kSecClass:
            (__bridge id)kSecClassGenericPassword,

        (__bridge id)kSecAttrService:
            service,

        (__bridge id)kSecAttrAccount:
            account,

        (__bridge id)kSecUseDataProtectionKeychain:
            @YES
    } mutableCopy];
}


int deliriuum_keychain_get(
    const char *service_c,
    const char *account_c,
    char *buffer,
    size_t buffer_len
)
{
    @autoreleasepool {

        if (
            service_c == NULL ||
            account_c == NULL ||
            buffer == NULL ||
            buffer_len == 0
        ) {
            return -1;
        }

        NSString *service =
            [NSString stringWithUTF8String:service_c];

        NSString *account =
            [NSString stringWithUTF8String:account_c];

        if (service == nil || account == nil) {
            return -1;
        }

        NSMutableDictionary *query =
            deliriuum_keychain_query(service, account);

        query[(__bridge id)kSecReturnData] = @YES;

        query[(__bridge id)kSecMatchLimit] =
            (__bridge id)kSecMatchLimitOne;

        CFTypeRef result = NULL;

        OSStatus status = SecItemCopyMatching(
            (__bridge CFDictionaryRef)query,
            &result
        );

        if (status == errSecItemNotFound) {
            return 1;
        }

        if (status != errSecSuccess || result == NULL) {
            if (result != NULL) {
                CFRelease(result);
            }
            return -1;
        }

        NSData *data = CFBridgingRelease(result);

        NSString *value =
            [[NSString alloc]
                initWithData:data
                    encoding:NSUTF8StringEncoding];

        if (value == nil) {
            return -1;
        }

        const char *utf8 = value.UTF8String;

        if (utf8 == NULL || strlen(utf8) >= buffer_len) {
            return -1;
        }

        snprintf(buffer, buffer_len, "%s", utf8);

        return 0;
    }
}


int deliriuum_keychain_set(
    const char *service_c,
    const char *account_c,
    const char *value_c
)
{
    @autoreleasepool {

        if (
            service_c == NULL ||
            account_c == NULL ||
            value_c == NULL
        ) {
            return -1;
        }

        NSString *service =
            [NSString stringWithUTF8String:service_c];

        NSString *account =
            [NSString stringWithUTF8String:account_c];

        NSString *value =
            [NSString stringWithUTF8String:value_c];

        if (
            service == nil ||
            account == nil ||
            value == nil
        ) {
            return -1;
        }

        NSData *data =
            [value dataUsingEncoding:NSUTF8StringEncoding];

        NSMutableDictionary *query =
            deliriuum_keychain_query(service, account);

        NSDictionary *updates = @{
            (__bridge id)kSecValueData: data
        };

        OSStatus status = SecItemUpdate(
            (__bridge CFDictionaryRef)query,
            (__bridge CFDictionaryRef)updates
        );

        if (status == errSecItemNotFound) {

            query[(__bridge id)kSecValueData] = data;

            query[(__bridge id)kSecAttrAccessible] =
                (__bridge id)
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;

            status = SecItemAdd(
                (__bridge CFDictionaryRef)query,
                NULL
            );
        }

        return status == errSecSuccess ? 0 : -1;
    }
}


int deliriuum_keychain_delete(
    const char *service_c,
    const char *account_c
)
{
    @autoreleasepool {

        if (service_c == NULL || account_c == NULL) {
            return -1;
        }

        NSString *service =
            [NSString stringWithUTF8String:service_c];

        NSString *account =
            [NSString stringWithUTF8String:account_c];

        if (service == nil || account == nil) {
            return -1;
        }

        NSMutableDictionary *query =
            deliriuum_keychain_query(service, account);

        OSStatus status = SecItemDelete(
            (__bridge CFDictionaryRef)query
        );

        if (
            status == errSecSuccess ||
            status == errSecItemNotFound
        ) {
            return 0;
        }

        return -1;
    }
}


/* ============================================================
   VPN UP
   ============================================================ */

int deliriuum_vpn_up(
    const char *config,
    char *error_buffer,
    size_t error_buffer_len
)
{
    @autoreleasepool {

        if (config == NULL) {
            set_error(
                error_buffer,
                error_buffer_len,
                @"Configuration VPN absente."
            );

            return -1;
        }

        NSString *wireguardConfig =
            [NSString stringWithUTF8String:config];

        if (wireguardConfig == nil) {
            set_error(
                error_buffer,
                error_buffer_len,
                @"Configuration VPN invalide."
            );

            return -1;
        }


        /* ----------------------------------------------------
           1. Activer la System Extension
           ---------------------------------------------------- */

        NSString *activationFailure = nil;

        if (!activate_system_extension(&activationFailure)) {
            set_error(
                error_buffer,
                error_buffer_len,
                activationFailure
                    ?: @"Impossible d’activer l’extension VPN."
            );

            return -1;
        }


        /* ----------------------------------------------------
           2. Charger / créer le VPN NetworkExtension
           ---------------------------------------------------- */

        dispatch_semaphore_t semaphore =
            dispatch_semaphore_create(0);

        __block int result = -1;
        __block NSString *failure = nil;

        [NETunnelProviderManager
            loadAllFromPreferencesWithCompletionHandler:
            ^(
                NSArray<NETunnelProviderManager *> *managers,
                NSError *error
            ) {

                if (error != nil) {
                    failure = error.localizedDescription;
                    dispatch_semaphore_signal(semaphore);
                    return;
                }

                NETunnelProviderManager *manager = nil;

                for (
                    NETunnelProviderManager *candidate
                    in managers
                ) {
                    NETunnelProviderProtocol *protocol =
                        (NETunnelProviderProtocol *)
                        candidate.protocolConfiguration;

                    if (
                        [protocol
                            isKindOfClass:
                                [NETunnelProviderProtocol class]]
                        &&
                        [protocol.providerBundleIdentifier
                            isEqualToString:
                                DeliriuumProviderBundleIdentifier]
                    ) {
                        manager = candidate;
                        break;
                    }
                }


                if (manager == nil) {
                    manager =
                        [[NETunnelProviderManager alloc] init];
                }


                NETunnelProviderProtocol *protocol =
                    [[NETunnelProviderProtocol alloc] init];

                protocol.providerBundleIdentifier =
                    DeliriuumProviderBundleIdentifier;

                protocol.serverAddress =
                    @"Deliriuum Direct";

                protocol.providerConfiguration = @{
                    @"wireguardConfig": wireguardConfig
                };

                manager.protocolConfiguration = protocol;
                manager.localizedDescription =
                    @"Deliriuum Direct";
                manager.enabled = YES;

                /*
                 * Reconnexion automatique gérée par macOS.
                 * Une déconnexion volontaire désactivera ce mode
                 * avant d'arrêter le tunnel.
                 */
                NEOnDemandRuleConnect *connectRule =
                    [[NEOnDemandRuleConnect alloc] init];

                manager.onDemandRules = @[connectRule];
                manager.onDemandEnabled = YES;

                DeliriuumManager = manager;


                [manager
                    saveToPreferencesWithCompletionHandler:
                    ^(NSError *saveError) {

                        if (saveError != nil) {
                            failure =
                                saveError.localizedDescription;

                            dispatch_semaphore_signal(
                                semaphore
                            );

                            return;
                        }


                        [manager
                            loadFromPreferencesWithCompletionHandler:
                            ^(NSError *loadError) {

                                if (loadError != nil) {
                                    failure =
                                        loadError.localizedDescription;

                                    dispatch_semaphore_signal(
                                        semaphore
                                    );

                                    return;
                                }


                                NSError *startError = nil;

                                BOOL started =
                                    [manager.connection
                                        startVPNTunnelAndReturnError:
                                            &startError];

                                if (!started) {
                                    failure =
                                        startError.localizedDescription
                                        ?: @"Impossible de démarrer le VPN.";

                                    dispatch_semaphore_signal(
                                        semaphore
                                    );

                                    return;
                                }


                                result = 0;

                                dispatch_semaphore_signal(
                                    semaphore
                                );
                            }
                        ];
                    }
                ];
            }
        ];


        dispatch_semaphore_wait(
            semaphore,
            DISPATCH_TIME_FOREVER
        );


        if (result != 0) {
            set_error(
                error_buffer,
                error_buffer_len,
                failure
                    ?: @"Erreur NetworkExtension."
            );
        }


        return result;
    }
}


/* ============================================================
   VPN DOWN
   ============================================================ */

int deliriuum_vpn_down(void)
{
    @autoreleasepool {

        if (DeliriuumManager == nil) {
            return 0;
        }

        /*
         * Déconnexion volontaire :
         * désactiver d'abord la reconnexion automatique,
         * sinon macOS pourrait relancer immédiatement le VPN.
         */
        DeliriuumManager.onDemandEnabled = NO;
        DeliriuumManager.onDemandRules = @[];

        dispatch_semaphore_t semaphore =
            dispatch_semaphore_create(0);

        __block BOOL saved = NO;

        [DeliriuumManager
            saveToPreferencesWithCompletionHandler:
            ^(NSError *error) {

                saved = (error == nil);
                dispatch_semaphore_signal(semaphore);
            }];

        dispatch_time_t timeout =
            dispatch_time(
                DISPATCH_TIME_NOW,
                10 * NSEC_PER_SEC
            );

        long waitResult =
            dispatch_semaphore_wait(semaphore, timeout);

        if (waitResult != 0 || !saved) {
            return -1;
        }

        [DeliriuumManager.connection stopVPNTunnel];

        return 0;
    }
}


/* ============================================================
   VPN STATUS
   ============================================================ */

int deliriuum_vpn_status(void)
{
    @autoreleasepool {

        if (DeliriuumManager == nil) {
            return 0;
        }

        switch (
            DeliriuumManager.connection.status
        ) {
            case NEVPNStatusConnected:
            case NEVPNStatusConnecting:
            case NEVPNStatusReasserting:
                return 1;

            default:
                return 0;
        }
    }
}
