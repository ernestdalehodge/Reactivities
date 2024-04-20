import { makeAutoObservable, runInAction } from "mobx";
import { User, UserFormValues } from "../models/user";
import agent from "../api/agent";
import { store } from "./store";
import { router } from "../router/Routes";

export default class UserStore {
    user: User | null = null;
    fbLoading = false;

    constructor() {
        makeAutoObservable(this)
    }

    get isLoggedIn() {
        return !!this.user;
    }

    login = async (creds: UserFormValues) => {
        const user = await agent.Acount.login(creds);
        store.commonStore.setToken(user.token);
        runInAction(() => this.user = user);
        router.navigate('/activities');
        store.modalStore.closeModal();
    }

    register = async (creds: UserFormValues) => {
        const user = await agent.Acount.register(creds);
        store.commonStore.setToken(user.token);
        runInAction(() => this.user = user);
        router.navigate('/activities');
        store.modalStore.closeModal();
    }

    logout = () => {
        store.commonStore.setToken(null);
        this.user = null;
        router.navigate('/');
    }

    getUser = async () => {

        try {
            const user = await agent.Acount.current();
            runInAction(() => this.user = user);
        } catch (error) {
            console.log(error);

        }
    }

    setImage = (image: string) => {
        if(this.user) this.user.image = image;
    }

    facebookLogin = async (accessToken: string) =>{
        try {
            this.fbLoading = true;
            const user = await agent.Acount.fbLogin(accessToken);
            store.commonStore.setToken(user.token);
            runInAction(() => {
                this.user = user;
                this.fbLoading = false;
            })
            router.navigate('/activities');
        } catch (error) {
            console.log(error);
            runInAction(() => this.fbLoading = false);
        }        
    }

    
}

