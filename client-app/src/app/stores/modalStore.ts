import { makeAutoObservable } from "mobx"

interface Modal {
    open: boolean;
    body: JSX.Element | null
}

export default class ModalStore {
    model: Modal = {
        open: false,
        body: null
    }

    constructor(){
        makeAutoObservable(this)
    }

    openModal = (content: JSX.Element) => {
        this.model.open = true;
        this.model.body = content;
    }

    closeModal = () => {
        this.model.open = false;
        this.model.body = null;
    }

    
}