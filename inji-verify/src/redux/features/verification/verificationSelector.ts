import {useAppSelector} from "../../hooks";
import {VerificationState} from "../../../types/data-types";

export const useVerificationFlowSelector = (selector: (state: VerificationState) => any) => selector(useAppSelector(state => state.verification));


