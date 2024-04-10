import { observer } from "mobx-react-lite";
import { useStore } from "../../stores/store";
import { Modal } from "semantic-ui-react";

export default observer(function ModalContainer(){
    const {modalStore} = useStore();
    return (
        <Modal open={modalStore.model.open} onClose={modalStore.closeModal} size='mini'>
            <Modal.Content>
                {modalStore.model.body}
            </Modal.Content>
        </Modal>
    )
})