import React, {useEffect} from 'react';
import LoaderWithBackdrop from "../commons/LoaderWithBackdrop";
import {useApplicationSelector} from "../../redux/features/application/applicationSelector";
import {useNavigate} from "react-router-dom";

function CheckingForInternetConnectivity(props: any) {
    const internetStatus = useApplicationSelector(state => state.internetConnectionStatus);
    const navigate = useNavigate();
    useEffect(() => {
        if (internetStatus === "OFFLINE") {
            navigate("/offline");
        }
    }, [internetStatus, navigate]);
    return internetStatus === "LOADING" ? (
        <LoaderWithBackdrop/>
    ) : <></>;
}

export default CheckingForInternetConnectivity;
