import {
    Component,
    NgZone,
    OnDestroy,
    OnInit,
    SystemJsNgModuleLoader,
} from '@angular/core';

import { ToasterService } from 'angular2-toaster';
import { Angulartics2 } from 'angulartics2';

import { ApiService } from 'jslib/abstractions/api.service';
import { I18nService } from 'jslib/abstractions/i18n.service';
import { PlatformUtilsService } from 'jslib/abstractions/platformUtils.service';

import { TwoFactorProviderType } from 'jslib/enums/twoFactorProviderType';
import { PasswordVerificationRequest } from 'jslib/models/request/passwordVerificationRequest';
import { 
    TwoFactorFido2DeleteRequestModel,
    TwoFactorFido2NewCredentialRequest, 
    TwoFactorFido2RegistrationRequest,
} from 'jslib/models/request/twoFactorFido2Request';
import {
    TwoFactorFido2Response,
} from 'jslib/models/response/twoFactorFido2Response';

import { TwoFactorBaseComponent } from './two-factor-base.component';

@Component({
    selector: 'app-two-factor-fido2',
    templateUrl: 'two-factor-fido2.component.html',
})
export class TwoFactorFido2Component extends TwoFactorBaseComponent implements OnInit {
    type = TwoFactorProviderType.Fido2; // type of twofactor
    keyName: string; // Name of the key to be register
    keyType: number; // type selected of the key to be register
    keyTypes:Array<TwoFactorFido2TypeData> = [
        new TwoFactorFido2TypeData(0, "platform", "Platform (FingerPrint, Windows Hello)"),
        new TwoFactorFido2TypeData(1, "cross-platform", "Cross-Platform (Yubikey)"),
    ]; // List of type of keys enable to select
    keys: any[]; // List of the user keys
    fido2Listening: boolean; // To check if the request to server or FIDO2 CLient is still in process
    fido2Request: TwoFactorFido2RegistrationRequest; // Response to the server, to register a key
    challengeFido2Promise: Promise<PublicKeyCredentialCreationOptions>; // Response from the server where contains the challenge to be sign
    formPromise: Promise<any>; //Aux variable

    constructor(apiService: ApiService, i18nService: I18nService,
        analytics: Angulartics2, toasterService: ToasterService,
        platformUtilsService: PlatformUtilsService, private ngZone: NgZone) {
        super(apiService, i18nService, analytics, toasterService, platformUtilsService);
        this.keyType = 1;
    }

    ngOnInit() {
    }

    auth(authResponse: any) {
        super.auth(authResponse);
        this.processResponse(authResponse.response); // process the response from the server where contains all keys that are register to him
    }

    submit() {
        if (this.fido2Request == null) { // Check if is ready to send a request to server
            // Should never happen.
            return Promise.reject();
        }
        return super.enable(async () => {
            // send to the server API the information to registe a new key to the user
            this.formPromise = this.apiService.postTwoFactorFido2Registration(this.fido2Request);
            const response = await this.formPromise;
            await this.processResponse(response); // process the response from the server where contains all keys that are register to him
        });
    }

    disable() {
        return super.disable(this.formPromise);
    }

    async remove(key: any) {
        if (key.removePromise != null) { // Check if isn't already been treated to be eliminated from the user
            return;
        }
        const name = key.name != null ? key.name : this.i18nService.t('fido2keyX', key.id); // If it doesn't have a name give one, exemple "FIDO2 Key 4"
        //Confirm if it wasn't a mistake to delete
        const confirmed = await this.platformUtilsService.showDialog(
            this.i18nService.t('removeFido2Confirmation'), name,
            this.i18nService.t('yes'), this.i18nService.t('no'), 'warning');
        if (!confirmed) { // cancel if was mistake
            return;
        }
        // Prepare the request of deleting the key selected
        const request = new TwoFactorFido2DeleteRequestModel(key.id, this.masterPasswordHash);
        try {
            // Sending the request
            key.removePromise = this.apiService.deleteTwoFactorFido2(request);
            const response = await key.removePromise;
            key.removePromise = null;
            await this.processResponse(response); // Update the keys that the user contains
        } catch { }
    }

    async readKey() {
        //Check if can read a new key
        if (this.keyType == null || this.keyType < 0 || this.keyType >= this.keyTypes.length || this.keyName == null || this.keyName == "") {
            // Should never happen.
            return Promise.reject();
        }
        try {
            this.resetFido2(true); // Delete any cache of previus actions
            var keyTypeValue = this.keyTypes.filter(k => k.id === this.keyType)[0].value; // Get the type selected, "Platform" or "Cross-Platform"
            const request = new TwoFactorFido2NewCredentialRequest(keyTypeValue, this.masterPasswordHash); // Prepare a request for a challenge to the server API
            console.log('Asking the server for the Fido2 challenge.');
            this.challengeFido2Promise = this.apiService.getTwoFactorFido2RegistrationChallenge(request); // Send a request for a challenge to the server API
            const challenge = await this.challengeFido2Promise;
            await this.readDevice(challenge); // Use the FIDO2 Client to sign the challenge
        } catch(err) { 
            console.error(err);
        } finally {
            this.fido2Listening = false; // end the regist of the new key
        }
    }

    private async readDevice(fido2Challenge: PublicKeyCredentialCreationOptions) {
        console.log('Waiting for de FIDO2 Client to Read Key.');
        this.resetFido2(true); // Delete any cache of previus actions
        // Ask to the browser on the FIDO2 Client to sign the challenge
        const cred = await navigator.credentials.create({
            publicKey: fido2Challenge,
        });
        console.log('Preparing the respose to the server.');
        // Preparing the request to the server to finalize the registe of the new key and save until the user click submit
        this.fido2Request = new TwoFactorFido2RegistrationRequest(this.keyName, cred as PublicKeyCredential, this.masterPasswordHash);
    }

    private resetFido2(listening = false) {
        this.fido2Request = null; // Delete any save request to submit
        this.fido2Listening = listening; // Change the indicator of the user to know if this app is thinking or not
    }

    private processResponse(response: TwoFactorFido2Response) {
        this.resetFido2(); // Delete any cache of previus actions
        this.keys = []; // Clean any FIDO2 keys saved 
        // Adapt the FIDO2 Key object to a new type object to help show information more clear
        response.fido2Keys.forEach((k) => 
            this.keys.push({
                id: k.id, 
                name: k.name,
                credentialType: k.credentialType,
                authenticatorType: k.authenticatorType,
                transports: k.transports,
                compromised: k.compromised,
                creationDate: k.creationDate,
                removePromise: null,
            })
        );
        this.keyName = null; //clean the name of the form for the new key
        this.enabled = response.enabled; // Check if the FIDO2 two-factor is enable
    }
}

class TwoFactorFido2TypeData {
    id: number;
    value: AuthenticatorAttachment;
    text: string;

    constructor(id: number, value: AuthenticatorAttachment, text: string) {
        this.id = id;
        this.value = value;
        this.text = text;
    }
}
