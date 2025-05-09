import Store from '@/store/store';
import {LocalStorageVal} from '@/utilities/helper_util';
import {
  ISlimUser,
  IStartupSettings,
  IUpdateUser,
  IUser
} from '@heimdall/common/interfaces';
import axios from 'axios';
import Vue from 'vue';
import {
  Action,
  getModule,
  Module,
  Mutation,
  VuexModule
} from 'vuex-module-decorators';
import {GroupsModule} from './groups';

const localToken = new LocalStorageVal<string | null>('auth_token');
const localUserID = new LocalStorageVal<string | null>('localUserID');

export interface IServerState {
  serverMode: boolean;
  serverUrl: string;
  loading: boolean;
  token: string;
  banner: string;
  classificationBannerColor: string;
  classificationBannerText: string;
  classificationBannerTextColor: string;
  enabledOAuth: string[];
  registrationEnabled: boolean;
  oidcName: string;
  ldap: boolean;
  localLoginEnabled: boolean;
  userInfo: IUser;
  tenableHostUrl: string;
  splunkHostUrl: string;
}

interface LoginData {
  userID: string;
  accessToken: string;
}

@Module({
  namespaced: true,
  dynamic: true,
  store: Store,
  name: 'ServerModule'
})
class Server extends VuexModule implements IServerState {
  apiKeysEnabled = false;
  banner = '';
  classificationBannerColor = '';
  classificationBannerText = '';
  classificationBannerTextColor = '';
  ldap = false;
  serverUrl = '';
  serverMode = false;
  registrationEnabled = true;
  localLoginEnabled = true;
  loading = true;
  enabledOAuth: string[] = [];
  allUsers: ISlimUser[] = [];
  oidcName = '';
  tenableHostUrl: string = '';
  splunkHostUrl: string = '';
  /** Our currently granted JWT token */
  token = '';
  /** Provide a sane default for userInfo in order to avoid having to null check it all the time */
  userInfo: IUser = {
    id: '',
    email: '',
    firstName: '',
    lastName: '',
    title: '',
    role: '',
    organization: '',
    loginCount: -1,
    lastLogin: undefined,
    creationMethod: '',
    createdAt: new Date(),
    updatedAt: new Date()
  };

  @Mutation
  SET_TOKEN(newToken: string) {
    this.token = newToken;
    localToken.set(newToken);
    axios.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
  }

  @Mutation
  SET_USERID(newID: string) {
    localUserID.set(newID);
    this.userInfo.id = newID;
  }

  @Mutation
  SET_STARTUP_SETTINGS(settings: IStartupSettings) {
    this.apiKeysEnabled = settings.apiKeysEnabled;
    this.banner = settings.banner;
    this.classificationBannerText = settings.classificationBannerText;
    this.classificationBannerColor = settings.classificationBannerColor;
    this.classificationBannerTextColor = settings.classificationBannerTextColor;
    this.enabledOAuth = settings.enabledOAuth;
    this.registrationEnabled = settings.registrationEnabled;
    this.oidcName = settings.oidcName;
    this.ldap = settings.ldap;
    this.localLoginEnabled = settings.localLoginEnabled;
    this.tenableHostUrl = settings.tenableHostUrl;
    this.splunkHostUrl = settings.splunkHostUrl;
  }

  @Mutation
  SET_USER_INFO(info: IUser) {
    this.userInfo = info;
  }

  @Mutation
  SET_SERVER() {
    this.serverMode = true;
  }

  @Mutation
  SET_LOADING(loading: boolean) {
    this.loading = loading;
  }

  @Mutation
  SET_ALL_USERS(users: ISlimUser[]) {
    this.allUsers = users;
  }

  @Mutation
  CLEAR_TOKEN() {
    localToken.clear();
  }

  @Mutation
  CLEAR_USERID() {
    localUserID.clear();
  }

  /* Try to find the Heimdall-Server backend. We have configured the Vue dev server to
   * automatically proxy VUE_APP_API_URL, so all we need to do is check if we get a response
   * at /server.
   *
   * Returns null if no server is found, or the server URL if one is.
   */
  @Action
  public async CheckForServer() {
    // This is the only function that manipulates the loading state. If loading is already set
    // then we have already loaded the server information and there is no need to check again.
    if (!this.loading) {
      return null;
    }

    return axios
      .get(`/server`)
      .then((response) => {
        if (response.status === 200) {
          // This means the server successfully responded and we are therefore in server mode
          this.context.commit('SET_SERVER');
          this.context.commit('SET_STARTUP_SETTINGS', response.data);
          const token = localToken.get() || Vue.$cookies.get('accessToken');
          const userID = localUserID.get() || Vue.$cookies.get('userID');
          Vue.$cookies.remove('accessToken');
          Vue.$cookies.remove('userID');
          if (token !== null) {
            this.context.commit('SET_TOKEN', token);
          }
          if (userID !== null) {
            this.context.commit('SET_USERID', userID);
          }
          return this.GetUserInfo();
        }
      })
      .catch((_) => {
        // If a error code is received from the server, this means the app is not in server mode
        // and there is therefore no action is required.
      })
      .then((_) => {
        this.context.commit('SET_LOADING', false);
      });
  }

  @Action
  public async handleLogin(data: LoginData) {
    this.context.commit('SET_USERID', data.userID);
    this.context.commit('SET_TOKEN', data.accessToken);
    this.GetUserInfo();
  }

  @Action
  public async Login(userInfo: {email: string; password: string}) {
    return axios.post<LoginData>('/authn/login', userInfo).then(({data}) => {
      this.handleLogin(data);
    });
  }

  @Action
  public async LoginLDAP(userInfo: {username: string; password: string}) {
    return axios
      .post<LoginData>('/authn/login/ldap', userInfo)
      .then(({data}) => {
        this.handleLogin(data);
      });
  }

  @Action
  public async LoginGithub(callbackCode: string | null) {
    return axios
      .get<LoginData>(`/authn/github/callback`, {
        params: {
          code: callbackCode
        }
      })
      .then(({data}) => {
        this.handleLogin(data);
      });
  }

  @Action
  public async Register(userInfo: {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
    passwordConfirmation: string;
    creationMethod: string;
  }) {
    return axios.post('/users', userInfo);
  }

  @Action
  public async updateUserInfo(user: {
    id: string;
    info: IUpdateUser;
  }): Promise<IUser> {
    return axios.put<IUser>(`/users/${user.id}`, user.info).then(({data}) => {
      if (this.userInfo.id === data.id) {
        this.context.commit('SET_USER_INFO', data);
      }
      return data;
    });
  }

  @Action
  public async GetUserInfo(): Promise<void> {
    if (this.userInfo.id) {
      const userInfo = await axios.get<IUser>(`/users/${this.userInfo.id}`);
      try {
        this.context.commit('SET_USER_INFO', userInfo.data);
      } catch {
        // If an error occurs fetching the users profile
        // then clear their token and refresh the page
        this.Logout();
      }
      await this.FetchAllUsers();
      await GroupsModule.FetchGroupData();
    }
  }

  @Action
  public FetchAllUsers() {
    return axios.get<ISlimUser[]>(`/users/user-find-all`).then(({data}) => {
      this.context.commit('SET_ALL_USERS', data);
    });
  }

  @Action
  public Logout(): Promise<void> {
    return axios
      .create() // Call axios.create() to skip the default interceptors setup in main.ts
      .post(`/users/logout`)
      .then(() => {
        this.CLEAR_USERID();
        this.CLEAR_TOKEN();
        location.replace('/login?logoff=true');
      })
      .catch((error) => {
        this.CLEAR_USERID();
        this.CLEAR_TOKEN();
        location.replace(
          `/login?logoff=true&error=${error.response.data.message}`
        );
      });
  }
}

export const ServerModule = getModule(Server);
